# Authentication

Players sign in with Google, Supabase, Firebase, Auth0 or any other service, as a Gobu plugin.

- `authentication/`: the plugin as a project has it: its `plugin.json`, `web/sign_in.html` (the page a web
  game's sign-in comes back to, written next to the game by the web export) and its libraries in `bin/`.
  Copy it into `<project>/plugins/` and enable it, or use **Add to Project** in Project Settings > Plugins
  (Gobu has a copy next to the editor, in `Engine/Binaries/plugins/authentication`).
- `Source/`: its code, C++ against Gobu's plugin interface only (`gobu_plugin.h`, version 3), so it is a
  library of its own: Gobu loads it only in a project that enabled it. Built with Gobu's forja: this
  repository goes in `ProjectGobu/Plugins/Authentication`, next to Gobu, listed in Gobu's
  `Engine/Source/external_plugins.txt`; then `forja build PluginAuthentication` builds the Windows DLL and the
  web side module (games without threads) into `authentication/bin` and copies the plugin next to the editor.

Settings: Project Settings > Authentication (Google, Supabase, Firebase, Auth0, Custom; a block per
platform). API: `Authentication.sign_in_with()`, `get_token()`, `check_token()`... Guide:
https://gobuengine.org/plugins/01-authentication
