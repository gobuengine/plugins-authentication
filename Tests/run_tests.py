# The Authentication plugin's tests: its real library, loaded by Gobu in three test projects, against a mock of
# Supabase Auth and of Google's sign-in (tools/mock_service.py, port 18765). A dedicated server checks the tokens
# of several games, each with its own APPDATA; the results are read from their logs.
#
#   python run_tests.py [path to gobu.windows.editor.x86_64.console.exe]
#
# Needs Python 3, openssl (the test keys) and Gobu built next to this repository (ProjectGobu/Gobu), or its
# console executable given. Build the plugin first: `forja build PluginAuthentication` in Gobu.
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, 'tools')
PLUGIN = os.path.join(os.path.dirname(HERE), 'authentication')
RUN = os.path.join(HERE, '.run')
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.normpath(os.path.join(HERE, '..', '..', '..', 'Gobu', 'Engine', 'Binaries', 'gobu.windows.editor.x86_64.console.exe'))
sys.path.insert(0, TOOLS)
from gen_vectors import vectors  # noqa: E402

failures = []


def check(what, ok):
	print(('  ok    ' if ok else '  FAIL  ') + what)
	if not ok:
		failures.append(what)


def project(name):
	# Each project has the plugin as a project gets it: its folder, with the libraries just built.
	path = os.path.join(HERE, 'projects', name)
	plugins = os.path.join(path, 'plugins', 'authentication')
	shutil.rmtree(plugins, ignore_errors=True)
	shutil.copytree(PLUGIN, plugins)
	return path


class Scenario:
	def __init__(self, name):
		self.logs = os.path.join(RUN, name)
		os.makedirs(self.logs, exist_ok=True)
		self.procs = []
		self.mock = subprocess.Popen([sys.executable, os.path.join(TOOLS, 'mock_service.py')], stdout=open(os.path.join(self.logs, 'mock.log'), 'w'), stderr=subprocess.STDOUT, cwd=TOOLS)
		time.sleep(1.5)

	def launch(self, name, proj, args, extra=(), follow=True, environment=None):
		appdata = os.path.join(RUN, 'appdata', os.path.basename(self.logs) + '_' + name)
		os.makedirs(appdata, exist_ok=True)
		env = dict(os.environ, APPDATA=appdata, **(environment or {}))
		if follow:
			env['GOBU_SIGN_IN_FOLLOW'] = '1'  # The game follows the sign-in page itself: no browser.
		log = open(os.path.join(self.logs, name + '.log'), 'w', encoding='utf-8')
		self.procs.append(subprocess.Popen([EXE, '--headless', *extra, '--path', proj, '--'] + args, stdout=log, stderr=subprocess.STDOUT, env=env))

	def end(self):
		for p in self.procs:
			if p.poll() is None:
				p.kill()
			p.wait()
		self.mock.kill()
		self.mock.wait()

	def log(self, name):
		with open(os.path.join(self.logs, name + '.log'), encoding='utf-8', errors='replace') as f:
			return f.read()


def login():
	print('Login: a server and its players (password logins, a guest, a forged and an expired token)')
	proj = project('login')
	s = Scenario('login')
	start = time.time()

	def at(seconds):
		time.sleep(max(0.0, seconds - (time.time() - start)))

	s.launch('srv', proj, ['--online-serve'], ['--verbose'], follow=False)
	at(4)
	s.launch('ana', proj, ['--email=ana@example.com', '--clave=secreto', '--online-join', '--online-player=p1', '--salir=40'], follow=False)
	at(5)
	s.launch('beto', proj, ['--email=beto@example.com', '--clave=secreto2', '--online-join', '--online-player=p2', '--salir=12'], follow=False)
	at(7)
	s.launch('guest', proj, ['--sin-login', '--unirse', '--online-player=p3', '--salir=8'], follow=False)
	at(8)
	s.launch('forged', proj, ['--token=' + vectors['TAMPERED'], '--online-join', '--online-player=p4', '--salir=8'], follow=False)
	at(9)
	s.launch('expired', proj, ['--email=viejo@example.com', '--clave=secreto3', '--online-join', '--online-player=p5', '--salir=8'], follow=False)
	at(10)
	s.launch('bad_password', proj, ['--email=ana@example.com', '--clave=mala', '--online-join', '--online-player=p6', '--salir=6'], follow=False)
	at(18)
	s.launch('ana_again', proj, ['--email=ana@example.com', '--clave=secreto', '--online-join', '--online-player=p7', '--salir=10'], follow=False)
	at(34)
	s.end()
	srv = s.log('srv')
	check('the plugin loads from its library', "Plugin 'authentication' loaded" in srv)
	check('two accounts get in', len(set(line.split('"')[1] for line in srv.splitlines() if 'logged in as "supabase:' in line)) == 2)
	check('a guest is turned away', 'turned away: This game needs a login.' in srv)
	check('a token of another service is turned away', 'turned away: The login is from a service this game does not take.' in srv)
	check('an expired token is turned away', 'turned away: The login expired: log in again.' in srv)
	check('a wrong password does not get a token', 'TMPLOGIN fallo 400' in s.log('bad_password'))
	ana = [line.split('"')[1] for line in srv.splitlines() if 'logged in as "supabase:' in line][0]
	check('an account that comes back goes on with its saved data', '"account:%s:marcador" goes on with its saved data' % ana in srv)


def multi():
	print('Several services at once: Supabase (password and Google), Custom (desktop and web clients)')
	proj = project('multi')
	s = Scenario('multi')
	s.launch('srv', proj, ['--online-serve=7784'], ['--verbose'])
	time.sleep(4)
	s.launch('email', proj, ['--email=ana@example.com', '--clave=secreto', '--online-join=127.0.0.1:7784', '--online-player=m1', '--salir=6'])
	s.launch('supabase_google', proj, ['--supabase-google', '--online-join=127.0.0.1:7784', '--online-player=m2', '--salir=6'])
	s.launch('custom', proj, ['--custom', '--online-join=127.0.0.1:7784', '--online-player=m3', '--salir=6'])
	s.launch('custom_other_game', proj, ['--custom-otro', '--online-join=127.0.0.1:7784', '--online-player=m6', '--salir=6'])
	s.launch('other_service', proj, ['--token=' + vectors['RS256_VALID'], '--online-join=127.0.0.1:7784', '--online-player=m4', '--salir=6'])
	time.sleep(14)
	s.launch('custom_web', proj, ['--custom-web', '--online-join=127.0.0.1:7784', '--online-player=m5', '--salir=4'])
	time.sleep(10)
	s.end()
	srv = s.log('srv')
	check('Supabase: password and Google sign-in', srv.count('logged in as "supabase:') == 2)
	check('Custom: the desktop and the web client are the same account', srv.count('logged in as "custom:') == 2 and len(set(line.split('"')[1] for line in srv.splitlines() if 'logged in as "custom:' in line)) == 1)
	check('a token for another game is turned away', 'turned away: The login is for another game.' in srv)
	check('a token of another service is turned away', 'turned away: The login is from a service this game does not take.' in srv)


def poki():
	print('Poki: a server checks Poki logins with Poki (a mock of its user-vault), with the team key it has')
	time.sleep(3)  # The games of the scenario before let go of the plugin's library.
	proj = project('multi')
	s = Scenario('poki')
	poki_env = {'GOBU_POKI_TEAM_KEY': 'test-team-key', 'GOBU_POKI_VERIFY_URL': 'http://127.0.0.1:18765/auth/verify-token'}
	s.launch('srv', proj, ['--online-serve=7786'], ['--verbose'], environment=poki_env)
	s.launch('srv_without_key', proj, ['--online-serve=7787'], ['--verbose'], environment={'GOBU_POKI_VERIFY_URL': poki_env['GOBU_POKI_VERIFY_URL']})
	time.sleep(4)
	s.launch('player', proj, ['--token=poki:poki-good', '--online-join=127.0.0.1:7786', '--online-player=k1', '--salir=6'])
	s.launch('old_token', proj, ['--token=poki:poki-old', '--online-join=127.0.0.1:7786', '--online-player=k2', '--salir=6'])
	s.launch('no_key', proj, ['--token=poki:poki-good', '--online-join=127.0.0.1:7787', '--online-player=k3', '--salir=6'])
	time.sleep(12)
	s.end()
	srv = s.log('srv')
	check('a Poki player gets in as "poki:<user_id>"', 'logged in as "poki:user-42"' in srv)
	check('a token Poki does not take is turned away', 'turned away: Poki did not take the login (an old or forged token).' in srv)
	check('the team key goes to Poki with the token', 'MOCK poki verify Bearer poki-good test-team-key' in s.log('mock'))
	check('a server without the team key turns Poki logins away', 'turned away: This server takes no Poki logins.' in s.log('srv_without_key'))


def sign_in():
	print('Signing in in the browser (followed by the game): Google, a refusal, Supabase with Google')
	google = project('google')
	login_proj = project('login')
	s = Scenario('sign_in')
	s.launch('srv_google', google, ['--online-serve=7781'], ['--verbose'])
	s.launch('srv_supabase', login_proj, ['--online-serve=7782'], ['--verbose'])
	time.sleep(4)
	s.launch('google', google, ['--google', '--online-join=127.0.0.1:7781', '--online-player=g1', '--salir=6'])
	s.launch('refused', google, ['--google-niega', '--online-join=127.0.0.1:7781', '--online-player=g2', '--salir=6'])
	s.launch('supabase', login_proj, ['--supabase-google', '--online-join=127.0.0.1:7782', '--online-player=s1', '--salir=6'])
	time.sleep(14)
	s.end()
	check('Google: signed in, and the server takes it', 'logged in as "custom:' in s.log('srv_google'))
	check('a refusal is sign_in_failed', 'TMPLOGIN no firmado The player said no.' in s.log('refused'))
	check('Supabase with Google: signed in, and the server takes it', 'logged in as "supabase:' in s.log('srv_supabase'))


shutil.rmtree(RUN, ignore_errors=True)  # Each run from nothing: no saved data, no logs of the last one.
if not os.path.exists(EXE):
	sys.exit('No Gobu at %s: give its console executable.' % EXE)
if not os.path.exists(os.path.join(PLUGIN, 'plugin.json')):
	sys.exit('No plugin folder at %s.' % PLUGIN)
login()
multi()
poki()
sign_in()
print('%d failed' % len(failures) if failures else 'All passed')
sys.exit(1 if failures else 0)
