# What a Gobu game uses of Supabase Auth and of Google's sign-in, as they answer it:
# - Supabase: a password login (POST /auth/v1/token?grant_type=password), a provider sign-in in the browser
#   (GET /auth/v1/authorize?provider=..., then POST /auth/v1/token?grant_type=pkce), the project's JWKS.
# - Google (OAuth 2.0 for installed apps): GET /o/oauth2/v2/auth, POST /token (with PKCE), GET /oauth2/v3/certs.
# The sign-in pages sign in at once: a 302 back to the game's address, as a browser would follow it.
import base64
import hashlib
import json
import secrets
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from jwt_tool import jwks, sign

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18765
ISS = 'http://127.0.0.1:%d/auth/v1' % PORT
USERS = {'ana@example.com': 'secreto', 'beto@example.com': 'secreto2', 'viejo@example.com': 'secreto3'}
GOOGLE_CLIENT = 'juego-de-prueba.apps.googleusercontent.com'
GOOGLE_SECRET = 'secreto-cliente'
JWKS = json.dumps(jwks())
codes = {}  # code -> what the sign-in asked


def challenge_of(verifier):
	return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()


def session_for(email):
	user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, email))
	now = int(time.time())
	exp = now - 3600 if email.startswith('viejo') else now + 3600  # viejo: a token that expired
	claims = {'aud': 'authenticated', 'exp': exp, 'iat': now - 7200 if exp < now else now, 'iss': ISS, 'sub': user_id, 'email': email, 'role': 'authenticated'}
	token = sign('ES256', claims, 'ec-1')
	return user_id, {'access_token': token, 'token_type': 'bearer', 'expires_in': 3600, 'expires_at': exp, 'refresh_token': 'r-' + user_id[:8], 'user': {'id': user_id, 'email': email}}


class Handler(BaseHTTPRequestHandler):
	def _send(self, code, text, headers=()):
		data = text.encode()
		self.send_response(code)
		self.send_header('Content-Type', 'application/json')
		self.send_header('Content-Length', str(len(data)))
		self.send_header('Access-Control-Allow-Origin', '*')
		for k, v in headers:
			self.send_header(k, v)
		self.end_headers()
		self.wfile.write(data)

	def _back(self, redirect, params):
		sep = '&' if '?' in redirect else '?'
		self._send(302, '', [('Location', redirect + sep + urlencode(params))])

	def do_OPTIONS(self):
		self.send_response(204)
		self.send_header('Access-Control-Allow-Origin', '*')
		self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
		self.send_header('Access-Control-Allow-Headers', 'apikey, content-type, accept, authorization')
		self.send_header('Content-Length', '0')
		self.end_headers()

	def do_GET(self):
		url = urlparse(self.path)
		q = {k: v[0] for k, v in parse_qs(url.query).items()}
		if url.path == '/auth/verify-token':
			# Poki's user-vault: the player's user_id for a token of this team's game.
			token = self.headers.get('Authorization', '')
			key = self.headers.get('X-Poki-Team-Api-Key', '')
			print('MOCK poki verify', token, key, flush=True)
			if key == 'test-team-key' and token == 'Bearer poki-good':
				self._send(200, '{"user_id": "user-42"}')
			else:
				self._send(401, '{"error": "invalid token"}')
		elif url.path in ('/auth/v1/.well-known/jwks.json', '/oauth2/v3/certs'):
			print('MOCK jwks', url.path, flush=True)
			self._send(200, JWKS)
		elif url.path == '/itch/user/oauth':
			# itch.io: the player accepts (here at once) and the browser goes back to the game with a code.
			missing = [k for k in ('client_id', 'redirect_uri', 'state', 'code_challenge') if k not in q]
			if missing or q.get('response_type') != 'code' or q.get('code_challenge_method') != 'S256' or q.get('scope') != 'profile:me':
				print('MOCK itch bad request', missing, q, flush=True)
				self._send(400, json.dumps({'error': 'invalid_request'}))
				return
			code = 'itch-' + secrets.token_urlsafe(8)
			codes[code] = {'kind': 'itch', 'client_id': q['client_id'], 'redirect_uri': q['redirect_uri'], 'code_challenge': q['code_challenge']}
			print('MOCK itch sign-in, back to %s' % q['redirect_uri'], flush=True)
			self._back(q['redirect_uri'], {'code': code, 'state': q['state']})
		elif url.path == '/itch/profile':
			token = self.headers.get('Authorization', '')
			print('MOCK itch profile', token, flush=True)
			if token == 'Bearer itch-access-1':
				self._send(200, json.dumps({'user': {'id': 4242, 'username': 'player1', 'display_name': 'Player One', 'cover_url': 'https://example.com/cover.png', 'gamer': True, 'developer': False, 'press_user': False, 'url': 'https://player1.itch.io'}}))
			else:
				self._send(401, json.dumps({'errors': ['invalid key']}))
		elif url.path == '/o/oauth2/v2/auth':
			# Google: the player signs in (here at once) and the browser goes back to the game.
			if q.get('response_type') == 'id_token':
				missing = [k for k in ('client_id', 'redirect_uri', 'state', 'nonce') if k not in q]
				if missing:
					print('MOCK google bad implicit request', missing, flush=True)
					self._send(400, json.dumps({'error': 'invalid_request'}))
					return
				now = int(time.time())
				id_token = sign('RS256', {'iss': 'https://accounts.google.com', 'azp': q['client_id'], 'aud': q['client_id'], 'sub': '110248495921238986420', 'email': 'jugadora@gmail.com', 'nonce': q['nonce'], 'iat': now, 'exp': now + 3599}, 'rsa-1')
				print('MOCK google implicit sign-in, back to %s' % q['redirect_uri'], flush=True)
				self._send(302, '', [('Location', q['redirect_uri'] + '#' + urlencode({'state': q['state'], 'id_token': id_token, 'authuser': '0'}))])
				return
			missing = [k for k in ('response_type', 'client_id', 'redirect_uri', 'state', 'code_challenge') if k not in q]
			if missing or q.get('code_challenge_method') != 'S256' or not q['redirect_uri'].startswith(('http://127.0.0.1:', 'http://localhost:')):
				print('MOCK google bad request', missing, q, flush=True)
				self._send(400, json.dumps({'error': 'invalid_request'}))
				return
			if q['client_id'] == 'niega':
				print('MOCK google denied', flush=True)
				self._back(q['redirect_uri'], {'error': 'access_denied', 'error_description': 'The player said no.', 'state': q['state']})
				return
			code = secrets.token_urlsafe(16)
			codes[code] = dict(q, kind='google')
			print('MOCK google sign-in, scope=%s, back to %s' % (q.get('scope'), q['redirect_uri']), flush=True)
			self._back(q['redirect_uri'], {'code': code, 'state': q['state'], 'scope': q.get('scope', '')})
		elif url.path == '/auth/v1/authorize':
			# Supabase: a provider of the project (it signs in with Google and comes back).
			if 'provider' not in q or 'redirect_to' not in q or q.get('code_challenge_method') != 's256':
				self._send(400, json.dumps({'msg': 'bad request'}))
				return
			code = str(uuid.uuid4())
			codes[code] = dict(q, kind='supabase')
			print('MOCK supabase sign-in with', q['provider'], flush=True)
			self._back(q['redirect_to'], {'code': code})
		else:
			self._send(404, '{}')

	def do_POST(self):
		url = urlparse(self.path)
		length = int(self.headers.get('Content-Length', 0))
		raw = self.rfile.read(length) if length else b''
		if url.path == '/itch/oauth/token':
			form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
			asked = codes.pop(form.get('code', ''), None)
			ok = (asked and asked['kind'] == 'itch' and form.get('grant_type') == 'authorization_code' and form.get('client_id') == asked['client_id']
				and form.get('redirect_uri') == asked['redirect_uri'] and 'client_secret' not in form
				and challenge_of(form.get('code_verifier', '')) == asked['code_challenge'])
			if not ok:
				print('MOCK itch token refused', form, flush=True)
				self._send(400, json.dumps({'error': 'invalid_grant'}))
				return
			print('MOCK itch token', flush=True)
			self._send(200, json.dumps({'access_token': 'itch-access-1', 'token_type': 'bearer', 'scope': 'profile:me'}))
			return
		if url.path == '/token':
			form = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
			asked = codes.pop(form.get('code', ''), None)
			ok = (asked and asked['kind'] == 'google' and form.get('grant_type') == 'authorization_code' and form.get('client_id') == asked['client_id']
				and form.get('redirect_uri') == asked['redirect_uri'] and form.get('client_secret') == GOOGLE_SECRET
				and challenge_of(form.get('code_verifier', '')) == asked['code_challenge'])
			if not ok:
				print('MOCK google token refused', form, flush=True)
				self._send(400, json.dumps({'error': 'invalid_grant', 'error_description': 'Bad Request'}))
				return
			now = int(time.time())
			id_token = sign('RS256', {'iss': 'https://accounts.google.com', 'azp': asked['client_id'], 'aud': asked['client_id'], 'sub': '110248495921238986420', 'email': 'jugadora@gmail.com', 'email_verified': True, 'iat': now, 'exp': now + 3599}, 'rsa-1')
			print('MOCK google token', flush=True)
			self._send(200, json.dumps({'access_token': 'ya29.' + secrets.token_urlsafe(20), 'expires_in': 3599, 'scope': asked.get('scope', ''), 'token_type': 'Bearer', 'id_token': id_token}))
			return
		if self.headers.get('apikey') != 'anon-key':
			self._send(401, json.dumps({'message': 'No API key found in request'}))
			return
		if url.path == '/auth/v1/token' and url.query == 'grant_type=pkce':
			body = json.loads(raw or b'{}')
			asked = codes.pop(body.get('auth_code', ''), None)
			if not asked or asked['kind'] != 'supabase' or challenge_of(body.get('code_verifier', '')) != asked['code_challenge']:
				print('MOCK supabase pkce refused', body, flush=True)
				self._send(400, json.dumps({'code': 400, 'error_code': 'bad_code_verifier', 'msg': 'code challenge does not match previously saved code verifier'}))
				return
			user_id, session = session_for('google-user@example.com')
			print('MOCK supabase pkce', user_id, flush=True)
			self._send(200, json.dumps(session))
			return
		if url.path == '/auth/v1/token' and url.query == 'grant_type=password':
			body = json.loads(raw or b'{}')
			email = body.get('email', '')
			if USERS.get(email) != body.get('password'):
				print('MOCK refused', email, flush=True)
				self._send(400, json.dumps({'code': 400, 'error_code': 'invalid_credentials', 'msg': 'Invalid login credentials'}))
				return
			user_id, session = session_for(email)
			print('MOCK login', email, user_id, flush=True)
			self._send(200, json.dumps(session))
			return
		self._send(404, '{}')

	def log_message(self, *args):
		pass


print('MOCK listening', PORT, flush=True)
ThreadingHTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
