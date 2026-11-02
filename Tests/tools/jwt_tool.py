# JWTs signed with openssl (no Python crypto package here): RS256, ES256, HS256, and the JWKS of the keys.
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RSA = os.path.join(HERE, 'rsa.pem')
EC = os.path.join(HERE, 'ec.pem')


def b64u(data):
	return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def run(args, data=None):
	return subprocess.run(args, input=data, capture_output=True, check=True).stdout


def ensure_keys():
	if not os.path.exists(RSA):
		run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', RSA])
	if not os.path.exists(EC):
		run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', EC])


def int_bytes(n):
	return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def jwks():
	ensure_keys()
	modulus = run(['openssl', 'rsa', '-in', RSA, '-noout', '-modulus']).decode().strip().split('=')[1]
	n = bytes.fromhex(modulus)
	der = run(['openssl', 'pkey', '-in', EC, '-pubout', '-outform', 'DER'])
	point = der[-65:]
	assert point[0] == 4
	return {'keys': [
		{'kty': 'RSA', 'kid': 'rsa-1', 'use': 'sig', 'alg': 'RS256', 'n': b64u(n), 'e': b64u(int_bytes(65537))},
		{'kty': 'EC', 'kid': 'ec-1', 'use': 'sig', 'alg': 'ES256', 'crv': 'P-256', 'x': b64u(point[1:33]), 'y': b64u(point[33:65])},
	]}


def der_to_raw(sig):
	# SEQUENCE { INTEGER r, INTEGER s } -> r || s (32 bytes each)
	assert sig[0] == 0x30
	i = 2 if sig[1] < 0x80 else 2 + (sig[1] & 0x7f)
	out = b''
	for _ in range(2):
		assert sig[i] == 0x02
		length = sig[i + 1]
		value = sig[i + 2:i + 2 + length].lstrip(b'\x00')
		out += value.rjust(32, b'\x00')
		i += 2 + length
	return out


def sign(alg, claims, kid=None, secret=b'', header_extra=None):
	ensure_keys()
	header = {'alg': alg, 'typ': 'JWT'}
	if kid:
		header['kid'] = kid
	if header_extra:
		header.update(header_extra)
	signing = b64u(json.dumps(header, separators=(',', ':')).encode()) + '.' + b64u(json.dumps(claims, separators=(',', ':')).encode())
	if alg == 'RS256':
		sig = run(['openssl', 'dgst', '-sha256', '-sign', RSA], signing.encode())
	elif alg == 'ES256':
		sig = der_to_raw(run(['openssl', 'dgst', '-sha256', '-sign', EC], signing.encode()))
	elif alg == 'HS256':
		sig = hmac.new(secret, signing.encode(), hashlib.sha256).digest()
	else:
		sig = b''
	return signing + '.' + b64u(sig)


if __name__ == '__main__':
	print(json.dumps(jwks()))
