/// package:http binding for ssl_public_key_pinning: a routing [PublicKeyPinningClient].
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:ssl_public_key_pinning/ssl_public_key_pinning.dart';

export 'package:ssl_public_key_pinning/ssl_public_key_pinning.dart';

const _redirectCodes = {301, 302, 303, 307, 308};

// Headers that must never travel across a host or scheme boundary on a
// redirect. Mirrors dart:io's own non-redirect header list.
const _sensitiveHeaders = {
  'authorization',
  'www-authenticate',
  'cookie',
  'cookie2',
};

/// A routing [http.Client]: requests to pinned hosts go through a
/// pin-enforcing channel (checked during the TLS handshake, fail-closed);
/// all other requests go through [inner] with normal CA validation.
///
/// Redirects are followed manually so every hop is re-routed - a redirect
/// can never move a request across the pin boundary unchecked.
///
/// Request bodies stream straight to the network and are never buffered.
/// On a 307 or 308 an [http.Request] is sent again from the bytes it already
/// holds. A streamed body ([http.StreamedRequest], [http.MultipartRequest])
/// can only be sent once, so for those the 307 or 308 response is returned
/// to the caller instead of being followed.
class PublicKeyPinningClient extends http.BaseClient {
  PublicKeyPinningClient(
    this._pinning, {
    http.Client? inner,
    void Function(HttpClient)? configurePinnedClient,
  }) : _inner = inner ?? http.Client() {
    final pinnedIo = _pinning.createPinnedHttpClient();
    configurePinnedClient?.call(pinnedIo);
    _pinned = IOClient(pinnedIo);
  }

  final PublicKeyPinning _pinning;
  final http.Client _inner;
  late final IOClient _pinned;

  bool _usesPinnedChannel(Uri url) =>
      url.scheme == 'https' && _pinning.isPinned(url.host);

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final stream = request.finalize();
    // An http.Request already holds its body in memory, so it can be sent
    // again. Anything else streams a one-shot body on the first hop, and a
    // later hop may only go without it once it is known to have been empty.
    Uint8List? body = request is http.Request ? request.bodyBytes : null;
    Stream<List<int>>? oneShot = body == null ? stream : null;
    var oneShotPending = oneShot != null;
    var oneShotBytes = 0;
    var oneShotDone = false;
    var method = request.method;
    var url = request.url;
    final headers = Map<String, String>.of(request.headers);
    final maxRedirects = request.followRedirects ? request.maxRedirects : 0;
    var hops = 0;

    while (true) {
      final http.BaseRequest hop;
      if (oneShot != null) {
        hop = _OneShotRequest(
          method,
          url,
          oneShot.transform(StreamTransformer.fromHandlers(
            handleData: (chunk, sink) {
              oneShotBytes += chunk.length;
              sink.add(chunk);
            },
            handleDone: (sink) {
              oneShotDone = true;
              sink.close();
            },
          )),
        )..contentLength = request.contentLength;
        oneShot = null;
      } else {
        hop = http.Request(method, url)..bodyBytes = body ?? Uint8List(0);
      }
      hop
        ..headers.addAll(headers)
        ..followRedirects = false
        ..persistentConnection = request.persistentConnection;

      final pinnedHop = _usesPinnedChannel(url);
      http.StreamedResponse response;
      try {
        response = await (pinnedHop ? _pinned : _inner).send(hop);
      } on HandshakeException {
        if (!pinnedHop) rethrow; // a real CA failure, not a pinning one
        throw PublicKeyPinningException(url.host,
            reason: _pinning.lastRejectionFor(url.host)?.toString());
      }

      final location = response.headers['location'];
      if (!_redirectCodes.contains(response.statusCode) ||
          location == null ||
          !request.followRedirects) {
        return response;
      }
      final toGet = {301, 302, 303}.contains(response.statusCode) &&
          method != 'GET' &&
          method != 'HEAD';
      if (!toGet && oneShotPending && !(oneShotDone && oneShotBytes == 0)) {
        // The next hop would need the streamed body again and it is gone.
        return response;
      }
      if (hops >= maxRedirects) {
        await response.stream.drain<void>();
        throw http.ClientException('Redirect limit exceeded', url);
      }
      hops++;
      await response.stream.drain<void>();

      final next = _resolveRedirect(url, location);
      if (toGet) {
        method = 'GET';
        body = null;
        oneShotPending = false;
        headers.removeWhere((k, _) {
          final key = k.toLowerCase();
          return key == 'content-length' || key == 'content-type';
        });
      }
      if (next.host.toLowerCase() != url.host.toLowerCase() ||
          next.scheme != url.scheme) {
        headers
            .removeWhere((k, _) => _sensitiveHeaders.contains(k.toLowerCase()));
      }
      url = next;
    }
  }

  Uri _resolveRedirect(Uri from, String location) {
    final Uri next;
    try {
      next = from.resolveUri(Uri.parse(location));
    } on FormatException {
      throw http.ClientException('Invalid redirect Location header', from);
    }
    if (next.scheme != 'http' && next.scheme != 'https') {
      throw http.ClientException(
          "Refusing redirect to unsupported scheme '${next.scheme}'", from);
    }
    return next;
  }

  @override
  void close() {
    _pinned.close();
    _inner.close();
  }
}

/// Sends a body stream that can be read only once.
class _OneShotRequest extends http.BaseRequest {
  _OneShotRequest(super.method, super.url, this._body);

  final Stream<List<int>> _body;

  @override
  http.ByteStream finalize() {
    super.finalize();
    return http.ByteStream(_body);
  }
}
