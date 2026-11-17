import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:ssl_public_key_pinning_http/ssl_public_key_pinning_http.dart';
import 'package:test/test.dart';

import 'support/test_ca.dart';
import 'support/tls_harness.dart';

void main() {
  late TlsTestServer pinnedServer; // cert: localhost_rsa2048, host: localhost
  late TlsTestServer plainServer; // cert: fresh CA-signed, host: 127.0.0.1
  late TestCa testCa;
  late String correctPin;
  const wrongPin = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  http.Client innerTrusting() {
    final ctx = SecurityContext()
      ..setTrustedCertificatesBytes(File(testCa.caCertPath).readAsBytesSync());
    return IOClient(HttpClient(context: ctx));
  }

  PublicKeyPinningClient clientWith(List<String> localhostPins,
          {http.Client? inner}) =>
      PublicKeyPinningClient(
          PublicKeyPinning(pins: {'localhost': localhostPins}),
          inner: inner ?? innerTrusting());

  setUpAll(() async {
    pinnedServer = await TlsTestServer.start(
        certPemPath: 'test/fixtures/localhost_rsa2048.crt.pem',
        keyPemPath: 'test/fixtures/localhost_rsa2048.key.pem');
    testCa = await TestCa.generate();
    plainServer = await TlsTestServer.start(
        certPemPath: testCa.leafCertPath, keyPemPath: testCa.leafKeyPath);
    final pins =
        json.decode(File('test/fixtures/expected_pins.json').readAsStringSync())
            as Map<String, dynamic>;
    correctPin = pins['localhost_rsa2048'] as String;
  });

  tearDownAll(() async {
    await pinnedServer.close();
    await plainServer.close();
    await testCa.cleanup();
  });

  test('1. routes pinned host through pin check', () async {
    final client = clientWith([correctPin]);
    final res = await client.get(pinnedServer.uri('localhost', '/ok'));
    expect(res.body, 'ok');
    client.close();
  });

  test(
      '2. wrong pin throws PublicKeyPinningException, zero requests reach server',
      () async {
    final before = pinnedServer.requestCount;
    final client = clientWith([wrongPin]);
    await expectLater(client.get(pinnedServer.uri('localhost', '/ok')),
        throwsA(isA<PublicKeyPinningException>()));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(pinnedServer.requestCount, before);
    client.close();
  });

  test('3. unpinned host goes through inner client with CA validation',
      () async {
    final client = clientWith([correctPin]);
    final res = await client.get(plainServer.uri('127.0.0.1', '/ok'));
    expect(res.body, 'ok');
    client.close();
  });

  test(
      '4. unpinned host with default inner fails CA validation (not a '
      'pinning error)', () async {
    final client = clientWith([correctPin], inner: http.Client());
    await expectLater(
        client.get(plainServer.uri('127.0.0.1', '/ok')),
        throwsA(predicate(
            (Object? e) => e is Exception && e is! PublicKeyPinningException)));
    client.close();
  });

  test('5. redirect pinned→pinned stays checked', () async {
    final client = clientWith([correctPin]);
    final res = await client.get(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}));
    expect(res.body, 'ok');
    client.close();
  });

  test('6. redirect unpinned→pinned re-applies the pin (bypass closed)',
      () async {
    final target = pinnedServer.uri('localhost', '/ok').toString();

    final bad = clientWith([wrongPin]);
    await expectLater(
        bad.get(plainServer
            .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target})),
        throwsA(isA<PublicKeyPinningException>()));
    bad.close();

    final good = clientWith([correctPin]);
    final res = await good.get(plainServer
        .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target}));
    expect(res.body, 'ok');
    good.close();
  });

  test('7. redirect pinned→unpinned goes through CA channel', () async {
    final target = plainServer.uri('127.0.0.1', '/ok').toString();
    final client = clientWith([correctPin]);
    final res = await client.get(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': target}));
    expect(res.body, 'ok');
    client.close();
  });

  test('8. 303 converts POST to GET and drops body', () async {
    final client = clientWith([correctPin]);
    final res = await client.post(
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '303', 'to': '/echo-method'}),
        body: 'payload');
    expect(res.body, 'GET');
    client.close();
  });

  test('9. 307 preserves method and body', () async {
    final client = clientWith([correctPin]);
    final res = await client.post(
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '307', 'to': '/echo-method'}),
        body: 'payload');
    expect(res.body, 'POST');
    client.close();
  });

  test('10. Authorization dropped on cross-host redirect', () async {
    final target = plainServer.uri('127.0.0.1', '/echo-auth').toString();
    final client = clientWith([correctPin]);
    final res = await client.get(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        headers: {'authorization': 'Bearer x'});
    expect(res.body, 'none');
    client.close();
  });

  test('11. Authorization kept on same-host redirect', () async {
    final client = clientWith([correctPin]);
    final res = await client.get(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': '/echo-auth'}),
        headers: {'authorization': 'Bearer x'});
    expect(res.body, 'Bearer x');
    client.close();
  });

  test('12. maxRedirects respected', () async {
    final client = clientWith([correctPin]);
    final loop = pinnedServer.uri('localhost', '/redirect',
        {'code': '302', 'to': '/redirect?code=302&to=%2Fok'});
    // /redirect -> /redirect -> /ok needs 2 hops; cap at 1.
    final req = http.Request('GET', loop)..maxRedirects = 1;
    await expectLater(client.send(req), throwsA(isA<http.ClientException>()));
    client.close();
  });

  test('13. followRedirects=false returns the 3xx as-is', () async {
    final client = clientWith([correctPin]);
    final req = http.Request(
        'GET',
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}))
      ..followRedirects = false;
    final res = await client.send(req);
    expect(res.statusCode, 302);
    await res.stream.drain<void>();
    client.close();
  });

  test('15. Cookie dropped on cross-host redirect', () async {
    final target = plainServer.uri('127.0.0.1', '/echo-cookie').toString();
    final client = clientWith([correctPin]);
    final res = await client.get(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        headers: {'cookie': 'session=abc'});
    expect(res.body, 'none');
    client.close();
  });

  test('16. Authorization dropped on https to http downgrade, same host',
      () async {
    final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    plain.listen((req) {
      req.response
        ..write(req.headers.value('authorization') ?? 'none')
        ..close();
    });
    final target = 'http://localhost:${plain.port}/echo-auth';
    final client = clientWith([correctPin]);
    final res = await client.get(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        headers: {'authorization': 'Bearer x'});
    expect(res.body, 'none');
    client.close();
    await plain.close(force: true);
  });

  test('14. http:// URL passes through inner untouched', () async {
    final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    plain.listen((req) {
      req.response
        ..write('plain')
        ..close();
    });
    final client = clientWith([correctPin]);
    final res =
        await client.get(Uri.parse('http://127.0.0.1:${plain.port}/anything'));
    expect(res.body, 'plain');
    client.close();
    await plain.close(force: true);
  });

  test('17. trailing-dot form of a pinned host is still pin-checked', () async {
    final bad = clientWith([wrongPin]);
    await expectLater(bad.get(pinnedServer.uri('localhost.', '/ok')),
        throwsA(isA<PublicKeyPinningException>()));
    bad.close();

    final good = clientWith([correctPin]);
    final res = await good.get(pinnedServer.uri('localhost.', '/ok'));
    expect(res.body, 'ok');
    good.close();
  });

  test('18. redirect to the trailing-dot form re-applies the pin', () async {
    final target = pinnedServer.uri('localhost.', '/ok').toString();
    final client = clientWith([wrongPin]);
    await expectLater(
        client.get(plainServer
            .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target})),
        throwsA(isA<PublicKeyPinningException>()));
    client.close();
  });

  test('19. malformed Location is a ClientException', () async {
    final client = clientWith([correctPin]);
    await expectLater(
        client.get(pinnedServer.uri(
            'localhost', '/redirect', {'code': '302', 'to': 'http://a:xx/'})),
        throwsA(isA<http.ClientException>()));
    client.close();
  });

  test('20. redirect to a non-http(s) scheme is refused', () async {
    final client = clientWith([correctPin]);
    for (final to in ['data:text/plain,hi', 'ftp://127.0.0.1/x']) {
      await expectLater(
          client.get(pinnedServer
              .uri('localhost', '/redirect', {'code': '302', 'to': to})),
          throwsA(isA<http.ClientException>()),
          reason: to);
    }
    client.close();
  });

  test('21. a streamed body reaches the server while it is still being sent',
      () async {
    final client = clientWith([correctPin]);
    final before = pinnedServer.requestCount;
    final req = http.StreamedRequest(
        'POST', pinnedServer.uri('localhost', '/echo-body'));
    final response = client.send(req);
    req.sink.add(List.filled(64 * 1024, 65));
    final reachedServer =
        await eventually(() => pinnedServer.requestCount > before);
    req.sink.add(List.filled(64 * 1024, 66));
    await req.sink.close();
    final res = await response;
    expect(reachedServer, isTrue,
        reason: 'the body must not be buffered before the request starts');
    expect((await res.stream.toBytes()).length, 128 * 1024);
    client.close();
  });

  test('22. 307 and 308 send an in-memory body again', () async {
    final client = clientWith([correctPin]);
    for (final code in ['307', '308']) {
      final res = await client.post(
          pinnedServer.uri(
              'localhost', '/redirect', {'code': code, 'to': '/echo-body'}),
          body: 'payload');
      expect(res.body, 'payload', reason: code);
    }
    client.close();
  });

  test('23. 307 and 308 on a one-shot body return the redirect as-is',
      () async {
    final client = clientWith([correctPin]);
    for (final code in ['307', '308']) {
      final url = pinnedServer
          .uri('localhost', '/redirect', {'code': code, 'to': '/echo-body'});
      final streamed = http.StreamedRequest('POST', url);
      final multipart = http.MultipartRequest('POST', url)
        ..fields['field'] = 'value';
      for (final req in [streamed, multipart]) {
        final response = client.send(req);
        if (req is http.StreamedRequest) {
          req.sink.add(utf8.encode('payload'));
          await req.sink.close();
        }
        final res = await response;
        expect(res.statusCode, int.parse(code),
            reason: '$code ${req.runtimeType}');
        expect(res.headers['location'], '/echo-body');
        await res.stream.drain<void>();
      }
    }
    client.close();
  });

  test('24. 303 still follows a one-shot body, as a GET', () async {
    final client = clientWith([correctPin]);
    final req = http.MultipartRequest(
        'POST',
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '303', 'to': '/echo-method'}))
      ..fields['field'] = 'value';
    final res = await client.send(req);
    expect(await res.stream.bytesToString(), 'GET');
    client.close();
  });

  test('25. a streamed request with an empty body still follows redirects',
      () async {
    final client = clientWith([correctPin]);
    final req = http.StreamedRequest(
        'GET',
        pinnedServer
            .uri('localhost', '/redirect', {'code': '307', 'to': '/ok'}));
    final response = client.send(req);
    await req.sink.close();
    final res = await response;
    expect(await res.stream.bytesToString(), 'ok');
    client.close();
  });

  test('26. a streamed body that was never read is not treated as empty',
      () async {
    final client = clientWith([correctPin], inner: _UnreadRedirectClient());
    final req =
        http.StreamedRequest('POST', Uri.parse('https://127.0.0.1:1/upload'));
    final response = client.send(req);
    req.sink.add(utf8.encode('payload'));
    unawaited(req.sink.close());
    final res = await response;
    expect(res.statusCode, 307);
    client.close();
  });
}

/// Stands in for the inner client: answers 307 without reading the body.
class _UnreadRedirectClient extends http.BaseClient {
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async =>
      http.StreamedResponse(const Stream.empty(), 307,
          headers: {'location': '/next'});
}

Future<bool> eventually(bool Function() condition) async {
  for (var i = 0; i < 100; i++) {
    if (condition()) return true;
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  return false;
}
