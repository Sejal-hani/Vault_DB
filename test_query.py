from vault_client import VaultClient

# 1. Initialize client
client = VaultClient()

# 2. Run query as customer
user = "alice@bank.com"
query = "SELECT * FROM app_data.accounts;"

print(f"User:  {user}")
print(f"Query: {query}\n")

results = client.execute(query, app_user=user)
print("Results:")
for row in results:
    print(" ", row)

# 3. Show audit trail record
print("\nRecorded Audit Log:")
log = client.get_audit_logs(limit=1)[0]
print(f"Log #{log[0]} | User: {log[2]} ({log[3]}) | Action: {log[4]} | Table: {log[5]} | Status: {log[6]}")

client.close()
