# plugins-authentication

Players sign in with Google, Supabase, Firebase, Auth0 or any other service, as a Gobu plugin.

- `authentication/`: the plugin as a project has it. Copy it into `<project>/plugins/` (or use **Add to
  Project** in Project Settings > Plugins, which writes it) and enable it. Its `plugin.json` says
  `"built_in": true`: its code is in Gobu, so it needs no library and works on every platform.
- `Source/`: its code, the Gobu module `authentication`. Gobu builds it from here: this repository goes in
  `ProjectGobu/Plugins/Authentication`, next to Gobu, as listed in Gobu's
  `Engine/Source/Modules/external_modules.txt`. Without it, Gobu builds without the plugin.

Settings: Project Settings > Authentication (Google, Supabase, Firebase, Auth0, Custom; a block per
platform). API: `Authentication.sign_in_with()`, `get_token()`, `check_token()`... Guide:
https://gobuengine.org/guide/14-authentication
