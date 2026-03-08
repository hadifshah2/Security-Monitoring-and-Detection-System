import csv

rows = [
    ["timestamp", "user", "ip", "country", "device", "result"],

    ["2026-03-01 08:00", "alice", "10.1.1.1", "USA", "Chrome", "success"],
    ["2026-03-01 08:04", "alice", "185.220.101.1", "Germany", "Chrome", "success"],

    ["2026-03-01 09:10", "bob", "10.1.1.5", "USA", "iPhone", "failed"],
    ["2026-03-01 09:11", "bob", "10.1.1.5", "USA", "iPhone", "failed"],
    ["2026-03-01 09:12", "bob", "10.1.1.5", "USA", "iPhone", "failed"],
    ["2026-03-01 09:13", "bob", "10.1.1.5", "USA", "iPhone", "failed"],
    ["2026-03-01 09:14", "bob", "10.1.1.5", "USA", "iPhone", "failed"],

    ["2026-03-01 02:30", "charlie", "77.91.124.55", "Germany", "Firefox", "success"],

    ["2026-03-01 12:00", "dana", "44.211.90.3", "USA", "Windows-Laptop", "success"],
    ["2026-03-01 12:02", "dana", "203.0.113.99", "Brazil", "Linux", "success"]
]

file = open("login_logs.csv", "w", newline="")
writer = csv.writer(file)

for row in rows:
    writer.writerow(row)

file.close()

print("login_logs.csv created successfully.")
