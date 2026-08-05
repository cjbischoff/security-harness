from app.db import run_query


def handler(request):
    user_input = request.args.get("q")
    return run_query(user_input)


@app.route('/widgets/<id>')
def get_widget(id):
    return run_query(id)
