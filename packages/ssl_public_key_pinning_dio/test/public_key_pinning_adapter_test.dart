import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:ssl_public_key_pinning_dio/ssl_public_key_pinning_dio.dart';
import 'package:test/test.dart';

import 'support/test_ca.dart';
import 'support/tls_harness.dart';

void main() {
  late TlsTestServer pinnedServer; // cert: localhost_rsa2048, host: localhost
  late TlsTestServer plainServer; // cert: fresh CA-signed, host: 127.0.0.1
  late TestCa testCa;
  late String correctPin;
  const wrongPin = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

  HttpClientAdapter trustingAdapter() =>
      IOHttpClientAdapter(createHttpClient: () {
        final ctx = SecurityContext()
          ..setTrustedCertificatesBytes(
              File(testCa.caCertPath).readAsBytesSync());
        return HttpClient(context: ctx);
      });

  Dio dioWith(List<String> localhostPins, {HttpClientAdapter? inner}) => Dio()
    ..httpClientAdapter = PublicKeyPinningAdapter(
        PublicKeyPinning(pins: {'localhost': localhostPins}),
        innerAdapter: inner ?? trustingAdapter());

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
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer.uri('localhost', '/ok'));
    expect(res.data, 'ok');
    dio.close();
  });

  test(
      '2. wrong pin: DioException.badCertificate wrapping '
      'PublicKeyPinningException, zero requests reach server', () async {
    final before = pinnedServer.requestCount;
    final dio = dioWith([wrongPin]);
    await expectLater(
        dio.getUri<String>(pinnedServer.uri('localhost', '/ok')),
        throwsA(isA<DioException>()
            .having((e) => e.type, 'type', DioExceptionType.badCertificate)
            .having(
                (e) => e.error, 'error', isA<PublicKeyPinningException>())));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(pinnedServer.requestCount, before);
    dio.close();
  });

  test('3. unpinned host goes through inner adapter with CA validation',
      () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(plainServer.uri('127.0.0.1', '/ok'));
    expect(res.data, 'ok');
    dio.close();
  });

  test(
      '4. unpinned host with default inner fails CA validation '
      '(not a pinning error)', () async {
    final dio = dioWith([correctPin], inner: IOHttpClientAdapter());
    await expectLater(
        dio.getUri<String>(plainServer.uri('127.0.0.1', '/ok')),
        throwsA(isA<DioException>().having(
            (e) => e.error, 'error', isNot(isA<PublicKeyPinningException>()))));
    dio.close();
  });

  test('5. redirect pinned→pinned stays checked', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}));
    expect(res.data, 'ok');
    dio.close();
  });

  test('6. redirect unpinned→pinned re-applies the pin (bypass closed)',
      () async {
    final target = pinnedServer.uri('localhost', '/ok').toString();

    final bad = dioWith([wrongPin]);
    await expectLater(
        bad.getUri<String>(plainServer
            .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target})),
        throwsA(isA<DioException>().having(
            (e) => e.error, 'error', isA<PublicKeyPinningException>())));
    bad.close();

    final good = dioWith([correctPin]);
    final res = await good.getUri<String>(plainServer
        .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target}));
    expect(res.data, 'ok');
    good.close();
  });

  test('7. redirect pinned→unpinned goes through CA channel', () async {
    final target = plainServer.uri('127.0.0.1', '/ok').toString();
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': target}));
    expect(res.data, 'ok');
    dio.close();
  });

  test('8. 303 converts POST to GET and drops body', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.postUri<String>(
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '303', 'to': '/echo-method'}),
        data: 'payload');
    expect(res.data, 'GET');
    dio.close();
  });

  test('9. 307 preserves method and body', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.postUri<String>(
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '307', 'to': '/echo-method'}),
        data: 'payload');
    expect(res.data, 'POST');
    dio.close();
  });

  test('10. Authorization dropped on cross-host redirect', () async {
    final target = plainServer.uri('127.0.0.1', '/echo-auth').toString();
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        options: Options(headers: {'authorization': 'Bearer x'}));
    expect(res.data, 'none');
    dio.close();
  });

  test('11. Authorization kept on same-host redirect', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': '/echo-auth'}),
        options: Options(headers: {'authorization': 'Bearer x'}));
    expect(res.data, 'Bearer x');
    dio.close();
  });

  test('12. maxRedirects respected', () async {
    final dio = dioWith([correctPin]);
    final loop = pinnedServer.uri('localhost', '/redirect',
        {'code': '302', 'to': '/redirect?code=302&to=%2Fok'});
    await expectLater(
        dio.getUri<String>(loop, options: Options(maxRedirects: 1)),
        throwsA(isA<DioException>()
            .having((e) => e.type, 'type', DioExceptionType.badResponse)));
    dio.close();
  });

  test('13. followRedirects=false returns the 3xx as-is', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}),
        options: Options(followRedirects: false, validateStatus: (_) => true));
    expect(res.statusCode, 302);
    dio.close();
  });

  test('16. Cookie dropped on cross-host redirect', () async {
    final target = plainServer.uri('127.0.0.1', '/echo-cookie').toString();
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        options: Options(headers: {'cookie': 'session=abc'}));
    expect(res.data, 'none');
    dio.close();
  });

  test('17. Authorization dropped on https to http downgrade, same host',
      () async {
    final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    plain.listen((req) {
      req.response
        ..write(req.headers.value('authorization') ?? 'none')
        ..close();
    });
    final target = 'http://localhost:${plain.port}/echo-auth';
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(
        pinnedServer
            .uri('localhost', '/redirect', {'code': '302', 'to': target}),
        options: Options(headers: {'authorization': 'Bearer x'}));
    expect(res.data, 'none');
    dio.close();
    await plain.close(force: true);
  });

  test('14. http:// URL passes through inner untouched', () async {
    final plain = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    plain.listen((req) {
      req.response
        ..write('plain')
        ..close();
    });
    final dio = dioWith([correctPin]);
    final res = await dio
        .getUri<String>(Uri.parse('http://127.0.0.1:${plain.port}/anything'));
    expect(res.data, 'plain');
    dio.close();
    await plain.close(force: true);
  });

  test('15. realUri reflects the final hop after redirects', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.getUri<String>(pinnedServer
        .uri('localhost', '/redirect', {'code': '302', 'to': '/ok'}));
    expect(res.realUri.path, '/ok');
    dio.close();
  });

  test('18. trailing-dot form of a pinned host is still pin-checked', () async {
    final bad = dioWith([wrongPin]);
    await expectLater(
        bad.getUri<String>(pinnedServer.uri('localhost.', '/ok')),
        throwsA(isA<DioException>().having(
            (e) => e.error, 'error', isA<PublicKeyPinningException>())));
    bad.close();

    final good = dioWith([correctPin]);
    final res =
        await good.getUri<String>(pinnedServer.uri('localhost.', '/ok'));
    expect(res.data, 'ok');
    good.close();
  });

  test('19. redirect to the trailing-dot form re-applies the pin', () async {
    final target = pinnedServer.uri('localhost.', '/ok').toString();
    final dio = dioWith([wrongPin]);
    await expectLater(
        dio.getUri<String>(plainServer
            .uri('127.0.0.1', '/redirect', {'code': '302', 'to': target})),
        throwsA(isA<DioException>().having(
            (e) => e.error, 'error', isA<PublicKeyPinningException>())));
    dio.close();
  });

  test('20. malformed Location is a badResponse DioException', () async {
    final dio = dioWith([correctPin]);
    await expectLater(
        dio.getUri<String>(pinnedServer.uri(
            'localhost', '/redirect', {'code': '302', 'to': 'http://a:xx/'})),
        throwsA(isA<DioException>()
            .having((e) => e.type, 'type', DioExceptionType.badResponse)));
    dio.close();
  });

  test('21. redirect to a non-http(s) scheme is refused', () async {
    final dio = dioWith([correctPin]);
    for (final to in ['data:text/plain,hi', 'ftp://127.0.0.1/x']) {
      await expectLater(
          dio.getUri<String>(pinnedServer
              .uri('localhost', '/redirect', {'code': '302', 'to': to})),
          throwsA(isA<DioException>()
              .having((e) => e.type, 'type', DioExceptionType.badResponse)),
          reason: to);
    }
    dio.close();
  });

  test('22. a stream body reaches the server while it is still being sent',
      () async {
    final dio = dioWith([correctPin]);
    final before = pinnedServer.requestCount;
    var reachedServer = false;
    Stream<List<int>> body() async* {
      yield List.filled(64 * 1024, 65);
      reachedServer =
          await eventually(() => pinnedServer.requestCount > before);
      yield List.filled(64 * 1024, 66);
    }

    final res = await dio.postUri<String>(
        pinnedServer.uri('localhost', '/echo-body'),
        data: body(),
        options: Options(headers: {Headers.contentLengthHeader: 128 * 1024}));
    expect(reachedServer, isTrue,
        reason: 'the body must not be buffered before the request starts');
    expect(res.data!.length, 128 * 1024);
    dio.close();
  });

  test('23. upload progress starts only once the body is being sent', () async {
    var progressEvents = 0;
    var progressBeforeSend = -1;
    final dio = dioWith([correctPin],
        inner:
            _ProbeAdapter(onFetch: () => progressBeforeSend = progressEvents));
    await dio.post<void>('https://127.0.0.1:1/upload',
        data: Uint8List(256 * 1024),
        onSendProgress: (_, __) => progressEvents++);
    expect(progressBeforeSend, 0);
    expect(progressEvents, greaterThan(0));
    dio.close();
  });

  test('24. 307 and 308 send an in-memory body again', () async {
    final dio = dioWith([correctPin]);
    for (final code in ['307', '308']) {
      final res = await dio.postUri<String>(
          pinnedServer.uri(
              'localhost', '/redirect', {'code': code, 'to': '/echo-body'}),
          data: 'payload');
      expect(res.data, 'payload', reason: code);
    }
    dio.close();
  });

  test('25. 307 and 308 on a one-shot body return the redirect as-is',
      () async {
    final dio = dioWith([correctPin]);
    for (final code in ['307', '308']) {
      final url = pinnedServer
          .uri('localhost', '/redirect', {'code': code, 'to': '/echo-body'});
      final bodies = <String, Object Function()>{
        'Stream': () => Stream.value(utf8.encode('payload')),
        'FormData': () => FormData.fromMap({'field': 'value'}),
      };
      for (final entry in bodies.entries) {
        final res = await dio.postUri<String>(url,
            data: entry.value(), options: Options(validateStatus: (_) => true));
        expect(res.statusCode, int.parse(code), reason: '$code ${entry.key}');
        expect(res.headers.value('location'), '/echo-body');
      }
    }
    dio.close();
  });

  test('26. 303 still follows a one-shot body, as a GET', () async {
    final dio = dioWith([correctPin]);
    final res = await dio.postUri<String>(
        pinnedServer.uri(
            'localhost', '/redirect', {'code': '303', 'to': '/echo-method'}),
        data: FormData.fromMap({'field': 'value'}));
    expect(res.data, 'GET');
    dio.close();
  });

  test('27. a body that was not fully sent is never replayed', () async {
    final dio = dioWith([correctPin],
        inner: _ProbeAdapter(status: 307, readBody: false));
    final res = await dio.post<String>('https://127.0.0.1:1/upload',
        data: 'payload', options: Options(validateStatus: (_) => true));
    expect(res.statusCode, 307);
    dio.close();
  });
}

Future<bool> eventually(bool Function() condition) async {
  for (var i = 0; i < 100; i++) {
    if (condition()) return true;
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
  return false;
}

/// Stands in for the inner adapter: reports when a request is handed over,
/// before any of its body is read, then answers with [status].
class _ProbeAdapter implements HttpClientAdapter {
  _ProbeAdapter({this.onFetch, this.status = 200, this.readBody = true});

  final void Function()? onFetch;
  final int status;
  final bool readBody;

  @override
  Future<ResponseBody> fetch(RequestOptions options,
      Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
    onFetch?.call();
    if (readBody) await requestStream?.drain<void>();
    return ResponseBody.fromString('', status, headers: {
      'location': ['/next'],
    });
  }

  @override
  void close({bool force = false}) {}
}
