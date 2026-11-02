# Tokens signed with the test keys (jwt_tool.py), for the "service" https://example.supabase.co: a game set up with
# the mock (tools/mock_service.py) does not take them, whatever their signature.
import json

from jwt_tool import jwks, sign

FUTURE = 4102444800  # 2100
PAST = 1000000000  # 2001
ISS = 'https://example.supabase.co/auth/v1'
base = {'sub': 'user-1', 'iss': ISS, 'aud': 'authenticated', 'exp': FUTURE}

vectors = {
	'JWKS': json.dumps(jwks(), separators=(',', ':')),
	'RS256_VALID': sign('RS256', base, 'rsa-1'),
	'ES256_VALID': sign('ES256', dict(base, sub='user-2'), 'ec-1'),
	'HS256_VALID': sign('HS256', dict(base, sub='user-3'), secret=b'super-secret'),
	'EXPIRED': sign('RS256', dict(base, exp=PAST), 'rsa-1'),
}
# The same claims with the signature of another token: tampered.
h, p, s = vectors['RS256_VALID'].split('.')
_, p2, _ = sign('RS256', dict(base, sub='admin'), 'rsa-1').split('.')
vectors['TAMPERED'] = '.'.join([h, p2, s])

if __name__ == '__main__':
	for name, value in vectors.items():
		print('%s = %s' % (name, value))
