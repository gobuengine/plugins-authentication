# Tests

`python run_tests.py`: the plugin's real library, loaded by Gobu in three test projects (`projects/`), against a
mock of Supabase Auth and of Google's sign-in (`tools/mock_service.py`, port 18765). A dedicated server and its
players, each with its own APPDATA:

- **Login**: password logins, a guest, a forged token, an expired one, a wrong password, an account that comes
  back with its saved data.
- **Poki**: a Poki login gets in as `poki:<user_id>` (a mock of Poki's user-vault, with the team key of
  `GOBU_POKI_TEAM_KEY`), one Poki does not take is turned away, and so is any on a server without the key.
- **CrazyGames**: a CrazyGames login gets in as `crazygames:<userId>` (checked with the mock's keys), and one for
  another game, an expired one or one without its prefix is turned away.
- **Several services**: Supabase (password and Google) and Custom (its desktop and web clients are the same
  account); a token for another game and one of another service are turned away.
- **Sign-in in the browser**: Google, a refusal, Supabase with Google; the game follows the sign-in page itself
  (`GOBU_SIGN_IN_FOLLOW`).

Needs Python 3, openssl (the test keys, made on the first run) and Gobu built next to this repository
(`ProjectGobu/Gobu`), or `python run_tests.py <gobu...console.exe>`. Build the plugin first
(`forja build PluginAuthentication` in Gobu): the runner copies `../authentication` into each project.
