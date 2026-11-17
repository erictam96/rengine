"""Compatibility layer over the `validators` package.

reNgine was written against validators 0.18. Newer releases (0.2x+) changed
semantics in ways that silently alter scan behaviour:
  * ipv4()/ipv6() accept CIDR ranges by default
  * ipv4_cidr()/ipv6_cidr() were removed
  * domain() rejects underscores ("my_host.example.com", "_dmarc.example.com")
  * url() rejects single-label hosts such as http://localhost:8000

Import this module instead of `validators` to keep the old behaviour.
"""
import validators as _v

ValidationError = _v.ValidationError


def ipv4(value):
	return bool(_v.ipv4(value, cidr=False))


def ipv6(value):
	return bool(_v.ipv6(value, cidr=False))


def ipv4_cidr(value):
	return bool(_v.ipv4(value, cidr=True, strict=True))


def ipv6_cidr(value):
	return bool(_v.ipv6(value, cidr=True, strict=True))


def domain(value):
	return bool(_v.domain(value, rfc_2782=True))


def url(value):
	return bool(_v.url(value, simple_host=True, rfc_2782=True))


def email(value):
	return bool(_v.email(value))
