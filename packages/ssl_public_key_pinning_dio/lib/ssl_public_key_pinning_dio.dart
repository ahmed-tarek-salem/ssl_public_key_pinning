/// Dio binding for ssl_public_key_pinning: a routing [PublicKeyPinningAdapter].
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
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

/// A routing [HttpClientAdapter]: requests to pinned hosts go through a
/// pin-enforcing channel (checked during the TLS handshake, fail-closed),
/// everything else through [innerAdapter] with normal CA validation.
///
/// Redirects are resolved inside this adapter so every hop is re-routed -
/// a redirect can never move a request across the pin boundary unchecked.
///
/// Request bodies stream straight to the network and are never buffered, so
/// upload progress follows the transfer. On a 307 or 308, in-memory data
/// (JSON, strings, bytes) is sent again. A [Stream] or [FormData] body can
/// only be sent once, so for those the 307 or 308 response is returned
/// as-is instead of being followed.
class PublicKeyPinningAdapter implements HttpClientAdapter {
  factory PublicKeyPinningAdapter(
    PublicKeyPinning pinning, {
    HttpClientAdapter? innerAdapter,
    void Function(HttpClient)? configurePinnedClient,
  }) {
    final pinned = IOHttpClientAdapter(createHttpClient: () {
      final client = pinning.createPinnedHttpClient();
      configurePinnedClient?.call(client);
      return client;
    });
    return PublicKeyPinningAdapter._(
        pinning, innerAdapter ?? IOHttpClientAdapter(), pinned);
  }

  PublicKeyPinningAdapter._(this._pinning, this._inner, this._pinned);

  final PublicKeyPinning _pinning;
  final HttpClientAdapter _inner;
  final IOHttpClientAdapter _pinned;

  bool _usesPinnedChannel(Uri url) =>
      url.scheme == 'https' && _pinning.isPinned(url.host);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    // Dio has already turned in-memory data into chunks it holds, so keeping
    // references to them as they stream past costs no copy and lets a
    // 307/308 send them again, once all of them have gone out. Stream and
    // FormData bodies are one-shot.
    final replayable = options.data is! Stream && options.data is! FormData;
    final sentChunks = <Uint8List>[];
    var fullySent = false;
    var hasBody = requestStream != null;
    Stream<Uint8List>? body = requestStream?.transform(
      StreamTransformer.fromHandlers(
        handleData: (chunk, sink) {
          if (replayable) sentChunks.add(chunk);
          sink.add(chunk);
        },
        handleDone: (sink) {
          fullySent = true;
          sink.close();
        },
      ),
    );

    var url = options.uri;
    var method = options.method;
    var headers = Map<String, dynamic>.of(options.headers);
    var dropContentHeaders = false;
    final followRedirects = options.followRedirects;
    final maxRedirects = followRedirects ? options.maxRedirects : 0;
    final redirects = <RedirectRecord>[];
    var hops = 0;

    while (true) {
      final hopOptions = options.copyWith(
        method: method,
        baseUrl: '',
        path: url.toString(),
        queryParameters: const {},
        headers: headers,
        followRedirects: false,
      );
      if (dropContentHeaders) {
        // copyWith re-applies the original contentType when the headers map
        // has none - undo that for hops converted to GET.
        hopOptions.headers.removeWhere((k, _) {
          final key = k.toLowerCase();
          return key == 'content-length' || key == 'content-type';
        });
      }

      final pinnedHop = _usesPinnedChannel(url);
      ResponseBody response;
      try {
        response = await (pinnedHop ? _pinned : _inner).fetch(
          hopOptions,
          body,
          cancelFuture,
        );
      } on HandshakeException {
        if (!pinnedHop) rethrow; // a real CA failure, not a pinning one
        throw DioException(
          requestOptions: options,
          type: DioExceptionType.badCertificate,
          error: PublicKeyPinningException(url.host,
              reason: _pinning.lastRejectionFor(url.host)?.toString()),
        );
      }

      final location = response.headers['location']?.first;
      if (!_redirectCodes.contains(response.statusCode) ||
          location == null ||
          !followRedirects) {
        if (redirects.isNotEmpty) response.redirects = redirects;
        return response;
      }
      final toGet = {301, 302, 303}.contains(response.statusCode) &&
          method != 'GET' &&
          method != 'HEAD';
      if (!toGet && hasBody && !(replayable && fullySent)) {
        // The next hop would need the body again and it cannot be rebuilt.
        if (redirects.isNotEmpty) response.redirects = redirects;
        return response;
      }
      if (hops >= maxRedirects) {
        await response.stream.drain<void>();
        throw DioException(
          requestOptions: options,
          type: DioExceptionType.badResponse,
          error: RedirectException('Redirect limit exceeded', const []),
        );
      }
      hops++;
      await response.stream.drain<void>();

      final next = _resolveRedirect(options, url, location);
      redirects.add(RedirectRecord(response.statusCode, method, next));
      if (toGet) {
        method = 'GET';
        hasBody = false;
        sentChunks.clear();
        dropContentHeaders = true;
        headers = Map.of(headers)
          ..removeWhere((k, _) {
            final key = k.toLowerCase();
            return key == 'content-length' || key == 'content-type';
          });
      }
      if (next.host.toLowerCase() != url.host.toLowerCase() ||
          next.scheme != url.scheme) {
        headers = Map.of(headers)
          ..removeWhere((k, _) => _sensitiveHeaders.contains(k.toLowerCase()));
      }
      body = hasBody ? Stream.fromIterable(sentChunks) : null;
      url = next;
    }
  }

  Uri _resolveRedirect(RequestOptions options, Uri from, String location) {
    final Uri next;
    try {
      next = from.resolveUri(Uri.parse(location));
    } on FormatException catch (e) {
      throw DioException(
        requestOptions: options,
        type: DioExceptionType.badResponse,
        error: e,
        message: 'Invalid redirect Location header',
      );
    }
    if (next.scheme != 'http' && next.scheme != 'https') {
      throw DioException(
        requestOptions: options,
        type: DioExceptionType.badResponse,
        message: "Refusing redirect to unsupported scheme '${next.scheme}'",
      );
    }
    return next;
  }

  @override
  void close({bool force = false}) {
    _pinned.close(force: force);
    _inner.close(force: force);
  }
}
