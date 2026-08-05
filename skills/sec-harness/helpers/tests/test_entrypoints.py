from sec_harness.entrypoints import classify_entry_point


def test_python_route_decorator_detected():
    lines = [
        "@app.route('/users/<id>')",
        "def get_user(id):",
        "    return db.fetch(id)",
    ]
    reason = classify_entry_point("py", lines, start=2, end=3)
    assert reason is not None
    assert "route" in reason


def test_python_non_contiguous_decorator_not_pulled_in():
    lines = [
        "@app.route('/users')",
        "",
        "def unrelated():",
        "    pass",
        "",
        "def internal_helper(x):",
        "    return x + 1",
    ]
    # internal_helper starts at line 6; the decorator two lines above it is
    # separated by a blank line and a different def, so it must NOT attach.
    reason = classify_entry_point("py", lines, start=6, end=7)
    assert reason is None


def test_python_user_input_access_detected():
    lines = [
        "def handler():",
        "    uid = request.args.get('id')",
        "    return uid",
    ]
    reason = classify_entry_point("py", lines, start=1, end=3)
    assert reason is not None
    assert "user-input" in reason


def test_python_cli_arg_detected():
    lines = [
        "def main():",
        "    target = sys.argv[1]",
        "    return target",
    ]
    reason = classify_entry_point("py", lines, start=1, end=3)
    assert reason is not None
    assert "cli-arg" in reason


def test_python_env_var_detected():
    lines = [
        "def load_config():",
        "    key = os.environ['API_KEY']",
        "    return key",
    ]
    reason = classify_entry_point("py", lines, start=1, end=3)
    assert reason is not None
    assert "env-var" in reason


def test_python_internal_function_not_flagged():
    lines = [
        "def add(a, b):",
        "    return a + b",
    ]
    assert classify_entry_point("py", lines, start=1, end=2) is None


def test_go_route_handler_detected():
    lines = [
        "func handler(w http.ResponseWriter, r *http.Request) {",
        "    router.GET(\"/users\", handler)",
        "}",
    ]
    reason = classify_entry_point("go", lines, start=1, end=3)
    assert reason is not None
    assert "route" in reason


def test_go_env_var_detected():
    lines = [
        "func loadConfig() string {",
        "    return os.Getenv(\"API_KEY\")",
        "}",
    ]
    reason = classify_entry_point("go", lines, start=1, end=3)
    assert reason is not None
    assert "env-var" in reason


def test_ruby_params_access_detected():
    lines = [
        "def show",
        "  id = params[:id]",
        "  id",
        "end",
    ]
    reason = classify_entry_point("rb", lines, start=1, end=4)
    assert reason is not None
    assert "user-input" in reason


def test_php_superglobal_detected():
    lines = [
        "function getUser() {",
        "    $id = $_GET['id'];",
        "    return $id;",
        "}",
    ]
    reason = classify_entry_point("php", lines, start=1, end=4)
    assert reason is not None
    assert "user-input" in reason


def test_js_express_route_detected():
    lines = [
        "app.get('/users/:id', function(req, res) {",
        "    res.send(req.params.id);",
        "});",
    ]
    reason = classify_entry_point("js", lines, start=1, end=3)
    assert reason is not None
    assert "route" in reason


def test_ts_process_argv_detected():
    lines = [
        "function main() {",
        "    const target = process.argv[2];",
        "    return target;",
        "}",
    ]
    reason = classify_entry_point("ts", lines, start=1, end=4)
    assert reason is not None
    assert "cli-arg" in reason


def test_unsupported_language_returns_none():
    lines = ["public class Main {", "    void run() {}", "}"]
    assert classify_entry_point("java", lines, start=1, end=3) is None
