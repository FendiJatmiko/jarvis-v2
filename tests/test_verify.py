from unittest.mock import MagicMock
from wp import verify as wp_verify

def _resp(text):
    r = MagicMock(); r.text = text; r.status_code = 200; return r

def test_verify_confirms_with_markers():
    http = MagicMock()
    http.get.return_value = _resp("WSH_dead_STARTuid=33(www-data)WSH_dead_END")
    out = wp_verify.verify({"url": "http://t/s.php", "token": "dead", "variant": "s.php"}, http)
    assert out is not None
    assert out["cmd_output"] == "uid=33(www-data)"

def test_verify_rejects_without_markers():
    http = MagicMock(); http.get.return_value = _resp("404 not found")
    assert wp_verify.verify({"url": "http://t/s.php", "token": "dead", "variant": "s.php"}, http) is None

def test_verify_handles_exception():
    http = MagicMock(); http.get.side_effect = Exception("timeout")
    assert wp_verify.verify({"url": "http://t/s.php", "token": "dead", "variant": "s.php"}, http) is None

def test_proof_recon_collects_outputs():
    http = MagicMock()
    http.get.side_effect = [
        _resp("WSH_dead_STARTuid=33WSH_dead_END"),
        _resp("WSH_dead_STARTLinux boxWSH_dead_END"),
        _resp("WSH_dead_START/var/wwwWSH_dead_END"),
    ]
    conf = {"url": "http://t/s.php", "token": "dead"}
    out = wp_verify.proof_recon(conf, http, cmds=("id","uname -a","pwd"))
    assert out["id"] == "uid=33"
    assert out["pwd"] == "/var/www"

def test_cleanup_reports_gone():
    http = MagicMock()
    http.get.side_effect = [_resp("removed"), _resp("404 gone")]  # rm call, then re-check
    conf = {"url": "http://t/wsh_dead.php", "token": "dead"}
    assert wp_verify.cleanup(conf, http) is True
