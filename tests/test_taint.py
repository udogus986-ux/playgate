"""Source → sink taint tracking."""

from __future__ import annotations

from playgate.models import Severity
from playgate.scan import scan

from .conftest import ids

KT = "app/src/main/java/com/x/Deep.kt"
JAVA = "app/src/main/java/com/x/Deep.java"


def _ids(gradle_project, code: str, path: str = KT) -> set[str]:
    return ids(scan(gradle_project(extra={path: code})))


def test_intent_url_to_webview(gradle_project) -> None:
    code = (
        "class Deep : Activity() {\n"
        "  override fun onCreate(b: Bundle?) {\n"
        '    val target = intent.getStringExtra("url")\n'
        "    val full = \"$target?ref=app\"\n"
        "    web.loadUrl(full)\n"
        "  }\n}\n"
    )
    assert "TAINT-WEBVIEW-URL" in _ids(gradle_project, code)


def test_constant_url_is_clean(gradle_project) -> None:
    code = (
        "class Deep : Activity() {\n"
        "  override fun onCreate(b: Bundle?) {\n"
        '    val name = intent.getStringExtra("name")\n'
        '    web.loadUrl("https://app.example.com/help")\n'
        "  }\n}\n"
    )
    assert "TAINT-WEBVIEW-URL" not in _ids(gradle_project, code)


def test_query_param_into_raw_sql(gradle_project) -> None:
    code = (
        "class Deep {\n"
        "  fun load(uri: Uri) {\n"
        '    val id = uri.getQueryParameter("id")\n'
        '    db.rawQuery("SELECT * FROM notes WHERE id = " + id, null)\n'
        "  }\n}\n"
    )
    assert "TAINT-SQLI" in _ids(gradle_project, code)


def test_parameterised_sql_is_clean(gradle_project) -> None:
    code = (
        "class Deep {\n"
        "  fun load(uri: Uri) {\n"
        '    val id = uri.getQueryParameter("id")\n'
        '    db.rawQuery("SELECT * FROM notes WHERE id = ?", arrayOf(id))\n'
        "  }\n}\n"
    )
    assert "TAINT-SQLI" not in _ids(gradle_project, code)


def test_intent_redirection_java(gradle_project) -> None:
    code = (
        "public class Deep extends Activity {\n"
        "  protected void onCreate(Bundle b) {\n"
        '    Intent next = getIntent().getParcelableExtra("next");\n'
        "    startActivity(next);\n"
        "  }\n}\n"
    )
    assert "TAINT-INTENT-REDIRECT" in _ids(gradle_project, code, JAVA)


def test_path_traversal(gradle_project) -> None:
    code = (
        "class Deep {\n"
        "  fun save(uri: Uri) {\n"
        "    val name = uri.lastPathSegment\n"
        "    val out = File(filesDir, name)\n"
        "  }\n}\n"
    )
    assert "TAINT-PATH" in _ids(gradle_project, code)


def test_validation_downgrades_to_medium(gradle_project) -> None:
    code = (
        "class Deep : Activity() {\n"
        "  override fun onCreate(b: Bundle?) {\n"
        '    val target = intent.getStringExtra("url")\n'
        '    if (Uri.parse(target).host == "app.example.com") {\n'
        "      web.loadUrl(target)\n"
        "    }\n"
        "  }\n}\n"
    )
    report = scan(gradle_project(extra={KT: code}))
    f = next(f for f in report.findings if f.id == "TAINT-WEBVIEW-URL")
    assert f.severity is Severity.MEDIUM


def test_flows_do_not_cross_functions(gradle_project) -> None:
    code = (
        "class Deep {\n"
        "  fun a() {\n"
        '    val url = intent.getStringExtra("u")\n'
        "  }\n"
        "  fun b(url: String) {\n"
        '    web.loadUrl("https://fixed.example.com")\n'
        "  }\n}\n"
    )
    assert "TAINT-WEBVIEW-URL" not in _ids(gradle_project, code)
