#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint webcrypto.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name                = 'webcrypto'
  s.version             = '0.1.1'
  s.summary             = 'Native support for package:webcrypto'
  s.description         = 'Wraps BoringSSL symbols required by the dart:ffi'\
                          'side of package:webcrypto'
  s.homepage            = 'https://github.com/google/webcrypto.dart'
  s.license             = { :file => '../LICENSE' }
  s.author              = { 'Jonas Finnemann Jensen' => 'jonasfj@google.com' }
  s.source              = { :path => '.' }
  s.swift_version       = '5.0'
  s.platform            = :ios, '9.0'
  s.dependency 'Flutter'

  s.public_header_files = 'Classes/**/*.h'
  s.source_files        = [
    'Classes/**/*',
    # Since we can't embed source from ../third_party/, we have created files
    # in ios/third_party/... which simply use #include "../...". This is a hack!
    'third_party/boringssl/**/*.{c,h}',
    'third_party/dart-sdk/**/*.{c,h}',
  ]
  s.compiler_flags      = [
    '-DOPENSSL_NO_ASM',
    '-DDOPENSSL_SMALL',
    '-GCC_WARN_INHIBIT_ALL_WARNINGS',
    '-w',
  ]

  s.pod_target_xcconfig = {
    # Enable equivalent of '-Isrc/include' to make '#include <openssl/...>' work
    'HEADER_SEARCH_PATHS' => [
      '$(PODS_TARGET_SRCROOT)/../third_party/boringssl/src/include',
      '$(PODS_TARGET_SRCROOT)/../third_party/dart-sdk/src/runtime',
    ],
    'DEFINES_MODULE' => 'YES',
    # Flutter.framework does not contain a i386 slice.
    # Only x86_64 simulators are supported.
    'VALID_ARCHS[sdk=iphonesimulator*]' => 'x86_64'
  }
end
