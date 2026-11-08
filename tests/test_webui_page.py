"""`/`、`/app.js`、`/app.css` 三份靜態內容的測試(#23;設計見 ADR-002 決策 5、10、11)。

**worker 沒有瀏覽器**(決策 14):前端的互動正確性是合併前的人側驗收項,不是這
檔的事。這裡驗的是三件可機驗的事:

  1. **路由與標頭**——`http.client` 打真 socket,三條路徑的狀態碼、`Content-Type`、
     CSP 與三個安全標頭、query 被忽略、`POST` 是 `405`。
  2. **頁面結構**——`html.parser` 解析 `PAGE_HTML`:三個表單的欄位與 `<label for>`、
     密碼欄的 `type` / `autocomplete`、`aria-live` 與 `role="alert"` 兩個區、
     以及「零 inline script / style、零 `on*`、零外部資源」。
  3. **JS 契約**——對 `APP_JS` 的純字串斷言(#23 主管層裁定 ①):`location.hash` /
     `history.replaceState` 在、storage / cookie / `eval(` / `innerHTML` 不在、
     每個 `fetch(` 的目標是三條 API 路徑之一的字面值且自帶兩個標頭、兩次密碼
     不一致在任何 `fetch(` 之前 `return`、三個密碼欄各恰有一處 `.value = ""`。

伺服器一律 `port=0` 起在 thread 裡、測試結束 `shutdown()`——用的是
`tests/conftest.py` 的 `server` 夾具(pytest 自動發現,不 import 測試檔)。
"""

from __future__ import annotations

import ast
import pathlib
import re
from html.parser import HTMLParser

import pytest

from qvault_core import webui
from tests.webui_client import send

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WEBUI_PATH = REPO_ROOT / "qvault_core" / "webui.py"
WEBUI_SOURCE = WEBUI_PATH.read_text(encoding="utf-8")

#: (路徑, 模組常數, Content-Type)——AC「路由與標頭」那三條,寫死在測試裡。
STATIC_ROUTES = (
    ("/", "PAGE_HTML", "text/html; charset=utf-8"),
    ("/app.js", "APP_JS", "text/javascript; charset=utf-8"),
    ("/app.css", "APP_CSS", "text/css; charset=utf-8"),
)

#: 三條 API 路徑,恰為 `fetch(` 允許的目標(決策 7)。
ALLOWED_FETCH_TARGETS = {"/api/inspect", "/api/encrypt", "/api/decrypt"}

#: 每個表單的欄位 `name`,依出現順序**恰為**這些(AC「頁面結構」第一條)。
EXPECTED_FIELDS = {
    "encrypt": ("path", "passphrase", "passphrase_confirm", "force"),
    "decrypt": ("path", "out_dir", "passphrase", "force"),
    "inspect": ("path",),
}

#: `id` → (`type`, `autocomplete`);`None` = 這一欄不該有 `autocomplete`。
EXPECTED_INPUT_ATTRS = {
    "encrypt_path": ("text", "off"),
    "encrypt_passphrase": ("password", "new-password"),
    "encrypt_passphrase_confirm": ("password", "new-password"),
    "encrypt_force": ("checkbox", None),
    "decrypt_path": ("text", "off"),
    "decrypt_out_dir": ("text", "off"),
    "decrypt_passphrase": ("password", "current-password"),
    "decrypt_force": ("checkbox", None),
    "inspect_path": ("text", "off"),
}


# ---------------------------------------------------------------- 工具


class _Page(HTMLParser):
    """用標準庫的 `html.parser` 把頁面拆成「標籤 + 屬性」(AC 指定的驗法)。

    不用正則掃 HTML:要問的問題是「這個 `<input>` 的 `autocomplete` 是什麼」、
    「`<script>` 裡有沒有內容」,那是解析器的問題,正則答不準。
    """

    def __init__(self, html: str) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.inputs_by_form: dict[str, list[dict[str, str]]] = {}
        self.label_targets: list[str] = []
        self.script_text: list[str] = []
        self._forms: list[str] = []
        self._in_script = False
        self.feed(html)
        self.close()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: (value if value is not None else "") for name, value in attrs}
        self.tags.append((tag, attributes))
        if tag == "form":
            self._forms.append(attributes.get("id", ""))
            self.inputs_by_form.setdefault(attributes.get("id", ""), [])
        elif tag == "input" and self._forms:
            self.inputs_by_form[self._forms[-1]].append(attributes)
        if tag == "label":
            self.label_targets.append(attributes.get("for", ""))
        if tag == "script":
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._forms:
            self._forms.pop()
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self.script_text.append(data)


@pytest.fixture(scope="module")
def page() -> _Page:
    return _Page(webui.PAGE_HTML)


def _fetch_calls(source: str) -> list[str]:
    """每個 `fetch(` 的實際參數原文(括號配對到底)。"""
    calls = []
    for match in re.finditer(r"\bfetch\s*\(", source):
        start = match.end() - 1
        depth = 0
        for index in range(start, len(source)):
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
                if depth == 0:
                    calls.append(source[start + 1 : index])
                    break
    return calls


# ================================================================ 路由與標頭


@pytest.mark.parametrize("path, constant, content_type", STATIC_ROUTES)
def test_each_static_route_is_200_with_its_own_content_type(
    server, path, constant, content_type
):
    """AC:三條路徑各 `200` + 各自的 `Content-Type`,body 逐 byte 等於模組常數。"""
    res = send(server, "GET", path)
    assert res.status == 200
    assert res.header("Content-Type") == content_type
    assert res.body == getattr(webui, constant).encode("utf-8")


@pytest.mark.parametrize("path, constant, content_type", STATIC_ROUTES)
def test_each_static_route_carries_the_csp_and_the_three_headers(
    server, path, constant, content_type
):
    """AC:三者都帶 #21 的 CSP 與三個安全標頭(`/app.js` 自己被開也一樣受管)。"""
    res = send(server, "GET", path)
    assert res.header("Content-Security-Policy") == webui.CONTENT_SECURITY_POLICY
    assert res.header("Content-Security-Policy") == (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; base-uri 'none'; "
        "form-action 'none'; frame-ancestors 'none'"
    )
    assert res.header("Cache-Control") == "no-store"
    assert res.header("X-Content-Type-Options") == "nosniff"
    assert res.header("Referrer-Policy") == "no-referrer"


@pytest.mark.parametrize("path, constant, _ct", STATIC_ROUTES)
def test_a_query_string_is_ignored_not_a_404(server, path, constant, _ct):
    """AC:`GET /app.js?x=1` → `200`(query 被忽略而非 404),body 一模一樣。

    `_route()` 砍掉 query 的那一刀同時是「token 不會進 access log」的理由(決策 9),
    所以這條順便守著它沒有被改成逐字比對整個 `self.path`。
    """
    res = send(server, "GET", f"{path}?x=1&y=2")
    assert res.status == 200
    assert res.body == getattr(webui, constant).encode("utf-8")


@pytest.mark.parametrize("path, _constant, _ct", STATIC_ROUTES)
def test_post_to_a_static_route_is_405(server, path, _constant, _ct):
    """AC:`POST /` → `405`(三份靜態內容都只收 GET / HEAD)。"""
    assert send(server, "POST", path, payload={"path": "/x"}).status == 405


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE", "OPTIONS"])
def test_other_methods_on_the_page_are_405(server, method):
    assert send(server, method, "/").status == 405


@pytest.mark.parametrize("path, constant, content_type", STATIC_ROUTES)
def test_head_gives_the_headers_without_a_body(server, path, constant, content_type):
    """`HEAD` 收得到完整標頭(含 `Content-Length`)但沒有 body。"""
    res = send(server, "HEAD", path)
    assert res.status == 200
    assert res.header("Content-Type") == content_type
    assert res.header("Content-Length") == str(len(getattr(webui, constant).encode("utf-8")))
    assert res.body == b""


def test_the_three_static_paths_are_the_module_constants(server):
    """路徑是常數,不是散在程式碼裡的字面值。"""
    assert webui.PAGE_PATH == "/"
    assert webui.APP_JS_PATH == "/app.js"
    assert webui.APP_CSS_PATH == "/app.css"
    assert set(webui._STATIC_RESPONSES) == {"/", "/app.js", "/app.css"}


def test_app_js_is_no_longer_one_of_the_404s(server):
    """#23 合法新增了這條路由(#23 主管層裁定),而其餘路徑照舊 `404`。"""
    assert send(server, "GET", "/app.js").status == 200
    for path in ("/app.mjs", "/app.css.map", "/static/app.js", "/APP.JS", "/app.js/"):
        assert send(server, "GET", path).status == 404, path


# ================================================================ 內容來自模組常數


def test_the_three_contents_are_plain_module_level_string_literals():
    """AC:內容由 `webui.py` 的**模組常數**提供(#23 主管層裁定 ②)。

    不是資源檔、不是 `importlib.resources`、不是相對於 `__file__` 的路徑——
    「wheel 裝起來之後 `/app.js` 還在不在」因此不是一個問題。
    """
    tree = ast.parse(WEBUI_SOURCE)
    assigned = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned[target.id] = node.value
    assert {"PAGE_HTML", "APP_JS", "APP_CSS"} <= set(assigned)
    for name in ("PAGE_HTML", "APP_JS", "APP_CSS"):
        value = assigned[name]
        assert isinstance(value, ast.Constant), name
        assert isinstance(value.value, str), name
        assert value.value == getattr(webui, name), name

    # 結構性守門:模組裡沒有任何資源查詢 / 檔案讀取的機制可以供這三份內容。
    # (掃 AST 而不是原始碼文字:docstring 裡**說明**「這裡沒有 importlib」的那
    # 句話不該讓這條紅。)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level:
            imported.add((node.module or "").split(".")[0])
    assert not imported & {"importlib", "pkgutil", "sysconfig", "shutil"}, imported
    names = {
        node.id if isinstance(node, ast.Name) else node.attr
        for node in ast.walk(tree)
        if isinstance(node, (ast.Name, ast.Attribute))
    }
    assert not names & {"__file__", "read_text", "read_bytes", "resources"}, names


def test_the_static_routes_do_not_read_the_cwd(server, tmp_path, monkeypatch):
    """AC:**不讀** cwd、不讀使用者路徑——把 cwd 換到一個空目錄再取三者。"""
    monkeypatch.chdir(tmp_path)
    assert list(tmp_path.iterdir()) == []
    for path, constant, _ct in STATIC_ROUTES:
        res = send(server, "GET", path)
        assert res.status == 200, path
        assert res.body == getattr(webui, constant).encode("utf-8"), path


def test_the_page_served_is_the_real_page_not_the_placeholder(server):
    """#21 的佔位頁已經不供人了(常數已於 #33 人類側接手時刪除)。"""
    body = send(server, "GET", "/").text
    assert body == webui.PAGE_HTML
    assert not hasattr(webui, "PLACEHOLDER_PAGE")
    assert "伺服器骨架已就緒" not in body
    assert body.startswith("<!DOCTYPE html>")


# ================================================================ 頁面結構


def test_the_page_has_exactly_the_three_forms(page):
    """AC:三個 `<form>`,`id` 分別 `encrypt`、`decrypt`、`inspect`。"""
    forms = [attrs for tag, attrs in page.tags if tag == "form"]
    assert len(forms) == 3
    assert [attrs.get("id") for attrs in forms] == ["encrypt", "decrypt", "inspect"]


@pytest.mark.parametrize("form_id", sorted(EXPECTED_FIELDS))
def test_each_form_has_exactly_the_named_fields(page, form_id):
    """AC:encrypt / decrypt / inspect 的欄位**恰為**那幾個(多一個也算紅)。"""
    names = tuple(attrs.get("name", "") for attrs in page.inputs_by_form[form_id])
    assert names == EXPECTED_FIELDS[form_id]


def test_every_input_has_a_label_pointing_at_its_own_id(page):
    """AC:每個 `<input>` 有對應的 `<label for="<id>">`,而且 `id` 全頁唯一。"""
    inputs = [attrs for tag, attrs in page.tags if tag == "input"]
    assert len(inputs) == len(EXPECTED_INPUT_ATTRS)
    ids = [attrs.get("id", "") for attrs in inputs]
    assert all(ids)
    assert len(set(ids)) == len(ids)
    assert sorted(page.label_targets) == sorted(ids)


@pytest.mark.parametrize("input_id", sorted(EXPECTED_INPUT_ATTRS))
def test_each_input_has_the_type_and_autocomplete_the_ac_names(page, input_id):
    """AC:密碼欄 `type="password"`;encrypt 兩欄 `new-password`、decrypt
    `current-password`;路徑欄(含 `out_dir`)`autocomplete="off"`。
    """
    expected_type, expected_autocomplete = EXPECTED_INPUT_ATTRS[input_id]
    attrs = next(a for tag, a in page.tags if tag == "input" and a.get("id") == input_id)
    assert attrs.get("type") == expected_type
    assert attrs.get("autocomplete") == expected_autocomplete


def test_the_only_password_inputs_are_the_three_the_ac_names(page):
    """反方向:頁面上沒有第四個密碼欄(例如有人加了「舊密碼」又忘了接 JS)。"""
    password_ids = {
        attrs.get("id")
        for tag, attrs in page.tags
        if tag == "input" and attrs.get("type") == "password"
    }
    assert password_ids == {
        input_id
        for input_id, (kind, _ac) in EXPECTED_INPUT_ATTRS.items()
        if kind == "password"
    }


def test_no_form_can_actually_submit(page):
    """AC:`action` 缺席或 `""`,且頁面上沒有 `method="post"` 的真表單送出。

    CSP 的 `form-action 'none'` 會擋掉真的送出,所以「看起來會送出的表單」是個
    使用者按下去沒反應的坑;送出一律由 `app.js` 攔 `submit`。
    """
    for tag, attrs in page.tags:
        if tag != "form":
            continue
        assert attrs.get("action", "") == "", attrs
        assert "method" not in attrs, attrs
    assert "method=" not in webui.PAGE_HTML.lower()
    assert "formaction" not in webui.PAGE_HTML.lower()


def test_one_polite_result_region_and_one_alert_error_region(page):
    """AC:一個 `aria-live="polite"` 的結果區 + 一個 `role="alert"` 的錯誤區。"""
    polite = [attrs for _tag, attrs in page.tags if attrs.get("aria-live") == "polite"]
    alerts = [attrs for _tag, attrs in page.tags if attrs.get("role") == "alert"]
    assert len(polite) == 1
    assert len(alerts) == 1
    assert polite[0].get("id") == "result"
    assert alerts[0].get("id") == "error"
    # 兩個區都是 `app.js` 唯一的寫入目標(JS 契約那段再驗一次它只用 textContent)。
    assert 'document.getElementById("result")' in webui.APP_JS
    assert 'document.getElementById("error")' in webui.APP_JS


def test_the_only_script_is_app_js_and_it_has_no_inline_content(page):
    """AC:HTML 內沒有帶內容的 `<script>`——只允許 `<script src="/app.js">`。"""
    scripts = [attrs for tag, attrs in page.tags if tag == "script"]
    assert [attrs.get("src") for attrs in scripts] == ["/app.js"]
    assert "".join(page.script_text).strip() == ""


def test_the_page_has_no_inline_style_no_handlers_and_no_external_resources(page):
    """AC:沒有 `<style>`、沒有 `style=`、沒有任何 `on*=`、外部資源為零。"""
    lowered = webui.PAGE_HTML.lower()
    for banned in ("<style", "javascript:", "style=", "data:", "http://", "https://"):
        assert banned not in lowered, banned
    assert re.search(r"\son[a-z]+\s*=", lowered) is None, "有 on* 屬性"
    for tag, attrs in page.tags:
        for name, value in attrs.items():
            assert not name.startswith("on"), (tag, name)
            if name in ("src", "href"):
                assert not value.startswith("//"), (tag, name, value)
                assert value.startswith("/"), (tag, name, value)
    # 外部資源的唯一來源會是 `<link>` / `<img>` / `<iframe>`:前者只指 `/app.css`。
    links = [attrs for tag, attrs in page.tags if tag == "link"]
    assert [attrs.get("href") for attrs in links] == ["/app.css"]
    assert not [tag for tag, _a in page.tags if tag in ("img", "iframe", "object", "embed")]


def test_app_css_pulls_in_nothing_from_outside():
    """樣式檔同樣零外部資源:沒有 `@import`、沒有任何位址引用、沒有自備字型。"""
    for banned in ("@import", "url(", "http://", "https://", "//"):
        assert banned not in webui.APP_CSS, banned


# ================================================================ JS 契約


def test_app_js_takes_the_token_from_the_fragment_and_clears_it():
    """AC:含 `location.hash` 讀取與 `history.replaceState`(載入後清掉 fragment)。"""
    assert "location.hash" in webui.APP_JS
    assert "history.replaceState" in webui.APP_JS
    # 兩者在**同一個**函式裡,而且是「先讀 fragment、再抹掉它」的順序:分開寫
    # 很容易長出「讀了但沒抹」或「抹了才讀」兩種版本。
    body = webui.APP_JS.split("function readTokenFromFragment()", 1)[1].split("\n}", 1)[0]
    assert body.index("location.hash") < body.index("history.replaceState")
    assert "token = " in body
    # 「清掉」要真的清掉:第三個參數恰為 `location.pathname`。換成 `location.href`
    # 或帶 `location.hash` 的寫法,token 會留在網址列(#33 複審 low)。
    assert 'history.replaceState(null, "", location.pathname);' in body
    assert "location.href" not in body


@pytest.mark.parametrize(
    "banned",
    ["localStorage", "sessionStorage", "document.cookie", "eval(", "innerHTML",
     "outerHTML", "insertAdjacentHTML", "document.write", "console.", "new Function"],
)
def test_app_js_never_persists_the_token_and_never_writes_html(banned):
    """AC:不含 storage / cookie / `eval(` / `innerHTML`(結果用 `textContent` 寫)。

    AC 點名的是前五個;後三個是同一條規矩的其他寫法——`innerHTML` 被擋掉之後
    最可能長出來的就是它們。
    """
    assert banned not in webui.APP_JS


def test_results_and_errors_are_written_with_text_content():
    """AC 的另一半:寫進兩個區的方式是 `textContent`。"""
    assert ".textContent = " in webui.APP_JS
    assert webui.APP_JS.count(".textContent") >= 4


def test_every_fetch_targets_one_of_the_three_api_paths():
    """AC:每個 `fetch(` 的第一個參數是三條 API 路徑之一的**字面值**。"""
    calls = _fetch_calls(webui.APP_JS)
    assert len(calls) == 3
    targets = []
    for call in calls:
        first = re.match(r'\s*"([^"]*)"', call)
        assert first is not None, call[:80]
        targets.append(first.group(1))
    assert set(targets) == ALLOWED_FETCH_TARGETS
    assert len(set(targets)) == len(targets)


def test_every_fetch_carries_the_token_and_the_json_content_type():
    """AC:每個 fetch 帶 `Authorization` 與 `Content-Type: application/json`。

    兩個標頭寫在**呼叫點**而不是共用的輔助函式,所以這條是逐個 `fetch(` 驗的。
    """
    calls = _fetch_calls(webui.APP_JS)
    assert len(calls) == 3
    for call in calls:
        assert '"Authorization": "Bearer " + token' in call, call[:80]
        assert '"Content-Type": "application/json"' in call, call[:80]
        assert '"POST"' in call, call[:80]


def _function_body(source: str, name: str) -> str:
    """`function <name>(...) { ... }` 的本體(大括號配對到底)。"""
    start = source.index("function " + name + "(")
    open_brace = source.index("{", start)
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : index]
    raise AssertionError("unbalanced braces in " + name)


def test_the_mismatched_confirmation_returns_before_any_fetch():
    """AC(#23 主管層裁定 ①a):兩次密碼不一致時**不送請求**。

    比的是 `onEncryptSubmit` 本體內的**控制流程**,不是全檔字串位置(#33 複審
    medium:舊寫法把整個 if 搬到 `sendEncrypt(` 之後、或刪掉 `return` 都仍然綠)。
    `!==` 那個分支的本體必須恰為「清空 → 顯示錯誤 → return」,而且整個分支
    結束在 `sendEncrypt(` 之前。
    """
    body = _function_body(webui.APP_JS, "onEncryptSubmit")
    compare = re.search(
        r"if \(fields\.passphrase_confirm\.value !== fields\.passphrase\.value\) \{", body
    )
    assert compare is not None, "找不到兩次密碼的 `!==` 分支"
    branch_end = body.index("}", compare.end())
    branch = " ".join(body[compare.end() : branch_end].split())
    assert branch == "clearPassphrases(); showError(MSG_MISMATCH); return;", branch
    assert branch_end < body.index("sendEncrypt("), "不一致的分支在送出之後才判"


def test_every_submit_handler_prevents_the_native_submission_first():
    """三個 submit handler 的第一句都是 `event.preventDefault();`——沒有它,
    瀏覽器會照 `<form>` 原生送出(CSP 的 `form-action 'none'` 會擋,但頁面會
    重新整理,token 隨之消失)。"""
    for name in ("onEncryptSubmit", "onDecryptSubmit", "onInspectSubmit"):
        first = _function_body(webui.APP_JS, name).strip().split("\n", 1)[0].strip()
        assert first == "event.preventDefault();", (name, first)


@pytest.mark.parametrize(
    "statement",
    ['encryptForm.elements.passphrase.value = ""',
     'encryptForm.elements.passphrase_confirm.value = ""',
     'decryptForm.elements.passphrase.value = ""'],
)
def test_each_password_field_is_cleared_exactly_once(statement):
    """AC(#23 主管層裁定 ①b):兩個密碼欄各有一處 `.value = ""`。

    這裡釘的是三欄(decrypt 的那一欄照同一條規矩清),而且**恰好各一處**:
    多一處通常代表有人另外加了一條清空路徑,少一處代表有一條路忘了清。
    """
    assert webui.APP_JS.count(statement) == 1


def test_nothing_else_assigns_an_empty_value():
    """承上:整份 `app.js` 的 `.value = ""` 恰好就是那三處。"""
    assert webui.APP_JS.count('.value = ""') == 3


def test_both_the_success_and_the_failure_path_clear_the_passphrases():
    """AC:送出**成功或失敗**後密碼欄都被清空——`settle` 的兩個回呼**各自**先
    清空(#33 複審 low:舊寫法只數次數,把兩次都搬進成功回呼仍然綠)。"""
    body = _function_body(webui.APP_JS, "settle")
    on_ok, on_fail = body.split("}, function (failure) {", 1)
    assert "pending.then(function (payload) {" in on_ok
    assert "clearPassphrases();" in on_ok.split("pending.then(function (payload) {", 1)[1]
    assert on_fail.strip().startswith("clearPassphrases();"), on_fail[:60]
    assert webui.APP_JS.count("clearPassphrases();") == 3  # 成功、失敗、兩次不一致


def test_a_written_path_must_come_back_as_a_string():
    """2xx 卻沒有 `out`(或回應不是 JSON)不得顯示成「已寫出:undefined」(#33 複審 low)。"""
    body = _function_body(webui.APP_JS, "showWrittenPath")
    assert 'if (typeof payload.out !== "string") {' in body
    assert "showError(MSG_BAD_RESPONSE);" in body
    parse = _function_body(webui.APP_JS, "oneJsonResponse")
    assert "return {};" not in parse
    assert "payload === null" in parse


@pytest.mark.parametrize("path", ["/", "/app.js", "/app.css"])
def test_static_routes_need_no_token(server, path):
    """瀏覽器第一次載入頁面時還沒有 token(它在 fragment 裡,伺服器看不到):
    三條靜態路由必須**不帶** `Authorization` 也拿得到(#33 複審 low)。"""
    assert send(server, "GET", path, token=None).status == 200


def test_app_js_is_strict_mode_and_mentions_no_outside_address():
    """`"use strict"` 在第一行;整份檔案沒有任何外部位址(CSP 之外的第二道)。"""
    assert webui.APP_JS.startswith('"use strict";')
    for banned in ("http://", "https://", "ws://"):
        assert banned not in webui.APP_JS, banned
