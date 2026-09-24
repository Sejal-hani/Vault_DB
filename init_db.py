import psycopg

def initialize_database():
    print("Initializing PostgreSQL database schemas...")
    
    with open("schema.sql", "r", encoding="utf-8") as f:
        schema_sql = f.read()

    try:
        with psycopg.connect(
            host="127.0.0.1",
            port=5432,
            user="postgres",
            password="nimit8222",
            dbname="postgres",
            autocommit=True
        ) as conn:
            with conn.cursor() as cur:
                cur.execute(schema_sql)
        print("Success: Database initialized and ready!")
    except Exception as e:
        print("Error initializing database:", e)

if __name__ == "__main__":
    initialize_database()
