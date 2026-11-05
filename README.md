# Authentication

Players sign in with Google, Supabase, Firebase, Auth0, Poki (a web game on Poki, with the Poki plugin) or any
other service, as a Gobu plugin.

- `authentication/`: the plugin as a project has it: its `plugin.json`, `web/sign_in.html` (the page a web
  game's sign-in comes back to, written next to the game by the web export), `doc_classes/` (the editor's help
  of the `Authentication` class) and its libraries in `bin/`.
  Install it from Gobu's **Edit > Plugins** (it downloads the latest release of this repository into
  `<project>/plugins/authentication` and enables it), or copy it there by hand. Its image in that window is
  `icon.svg`. A release has the three files of `forja package plugin <this repository>/authentication` (run
  from Gobu): `authentication.zip`, `plugin.json` (with the package's size and SHA-256) and `icon.svg`.
- `Source/`: its code, C++ against Gobu's plugin interface only (`gobu_plugin.h`, version 3), so it is a
  library of its own: Gobu loads it only in a project that enabled it. Built with Gobu's forja: this
  repository goes in `ProjectGobu/Plugins/Authentication`, next to Gobu, listed in Gobu's
  `Engine/Source/external_plugins.txt`; then `forja build PluginAuthentication` builds the Windows DLL, the
  web side module (games without threads) and the Android library (arm64-v8a, with the NDK forja provides)
  into `authentication/bin` and copies the plugin next to the editor.

Settings: Project Settings > Authentication (Google, Supabase, Firebase, Auth0, Custom; a block per
platform). API: `Authentication.sign_in_with()`, `get_token()`, `check_token()`... Guide:
https://gobuengine.org/plugins/01-authentication
