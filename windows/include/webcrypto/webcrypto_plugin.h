#ifndef FLUTTER_PLUGIN_WEBCRYPTO_PLUGIN_H_
#define FLUTTER_PLUGIN_WEBCRYPTO_PLUGIN_H_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

#ifdef FLUTTER_PLUGIN_IMPL
#define FLUTTER_PLUGIN_EXPORT __declspec(dllexport)
#else
#define FLUTTER_PLUGIN_EXPORT __declspec(dllimport)
#endif

#if defined(__cplusplus)
extern "C" {
#endif

FLUTTER_PLUGIN_EXPORT void WebcryptoPluginRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar);

#if defined(__cplusplus)
}  // extern "C"
#endif

namespace webcrypto {

class WebcryptoPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  WebcryptoPlugin();

  virtual ~WebcryptoPlugin();

  // Disallow copy and assign.
  WebcryptoPlugin(const WebcryptoPlugin&) = delete;
  WebcryptoPlugin& operator=(const WebcryptoPlugin&) = delete;

  // Called when a method is called on this plugin's channel from Dart.
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

}  // namespace webcrypto

#endif  // FLUTTER_PLUGIN_WEBCRYPTO_PLUGIN_H_
