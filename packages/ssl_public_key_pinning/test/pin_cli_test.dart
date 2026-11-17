import 'dart:io';

import 'package:test/test.dart';

void main() {
  for (final port in ['0', '-1', '70000']) {
    test('rejects out-of-range port $port with a usage error', () async {
      final result = await Process.run(
          Platform.resolvedExecutable, ['bin/pin.dart', 'localhost', port]);
      expect(result.exitCode, 64);
      expect(result.stderr, contains('Invalid port'));
    });
  }
}
