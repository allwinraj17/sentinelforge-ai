from app.agents.auto_fix_agent import generate_fix


vulnerability = {
    "check_id": "sql-injection",
    "extra": {
        "message": "User input is directly concatenated into a SQL query"
    },
    "path": "app.py",
    "start": {
        "line": 10
    }
}


source_code = """
query = "SELECT * FROM users WHERE id=" + user_id
cursor.execute(query)
"""


result = generate_fix(vulnerability, source_code)

print("\n================ AUTO-FIX RESULT ================\n")
print(result)
print("\n===================================================\n")