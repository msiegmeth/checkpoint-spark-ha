"""Offline IP -> country lookup (DB-IP lite CSV format)."""

import gzip

from custom_components.checkpoint_spark.geo import GeoIP


class _Config:
    def __init__(self, path):
        self._path = path

    def path(self, *parts):
        return self._path


class _Hass:
    def __init__(self, path):
        self.config = _Config(path)


def test_lookup(tmp_path) -> None:
    f = tmp_path / "dbip.csv.gz"
    f.write_bytes(gzip.compress(b"1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n2001:db8::,2001:db8::ffff,DE\n176.65.148.0,176.65.148.255,NL\n"))
    geo = GeoIP(_Hass(str(f)))
    geo._load()
    assert geo.ready
    assert geo.lookup("8.8.8.8") == "US"
    assert geo.lookup("176.65.148.226") == "NL"
    assert geo.lookup("9.9.9.9") is None          # not in a range
    assert geo.lookup("192.168.1.2") is None      # private
    assert geo.lookup("not-an-ip") is None
    assert geo.lookup("8.8.8.8") == "US"          # cached
