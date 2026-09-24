from vault_client import VaultClient

def run_test():
    try:
        client = VaultClient()
    except Exception as e:
        print("Could not connect to PostgreSQL:", e)
        return

    # Configuration for test query
    current_user = "sarah@company.com"
    current_role = "writer"
    sql_query = "SELECT id, name, email FROM app_data.customers;"

    print(f"Running as: {current_user} (Role: {current_role})")
    print(f"Query: {sql_query}")

    # Execute query through middleware
    try:
        results = client.execute(
            query=sql_query,
            app_user=current_user,
            user_role=current_role
        )
        print("\nQuery Results:")
        for row in results:
            print(" ", row)

    except PermissionError as e:
        print("\nSecurity Block:", e)
    except Exception as e:
        print("\nDatabase Error:", e)

    # Show generated audit trail
    print("\nRecorded Audit Log:")
    logs = client.get_audit_logs(limit=1)
    if logs:
        l = logs[0]
        print(f"Log ID:     {l[0]}")
        print(f"Timestamp:  {str(l[1])[:19]}")
        print(f"User:       {l[2]} ({l[3]})")
        print(f"Action:     {l[4]}")
        print(f"Table:      {l[5]}")
        print(f"Sensitive:  {'YES' if l[7] else 'NO'}")
        print(f"Status:     {l[8]}")

    client.close()

if __name__ == "__main__":
    run_test()
