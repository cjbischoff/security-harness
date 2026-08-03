def run_query(sql):
    cursor.execute(sql)
    return cursor.fetchall()
