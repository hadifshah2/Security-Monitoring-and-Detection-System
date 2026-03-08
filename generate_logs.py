import csv
import random
from datetime import datetime, timedelta

users = ["alice", "bob", "charlie", "dana", "eve"]

countries = ["USA", "Germany", "Brazil", "UK", "Canada"]

devices = ["Chrome", "Firefox", "iPhone", "Android", "Windows"]

ips = [
    "8.8.8.8",
    "1.1.1.1",
    "185.220.101.1",
    "44.211.90.3",
    "77.91.124.55"
]

rows = [["timestamp", "user", "ip", "country", "device", "result"]]

start_time = datetime(2026, 3, 1, 8, 0)

for i in range(500):

    user = random.choice(users)
    ip = random.choice(ips)
    country = random.choice(countries)
    device = random.choice(devices)

    # Mostly successful logins
    result = random.choices(["success", "failed"], weights=[0.9, 0.1])[0]

    timestamp = start_time + timedelta(minutes=random.randint(0, 5000))

    rows.append([
        timestamp.strftime("%Y-%m-%d %H:%M"),
        user,
        ip,
        country,
        device,
        result
    ])

file = open("login_logs.csv", "w", newline="")
writer = csv.writer(file)

for row in rows:
    writer.writerow(row)

file.close()

print("Generated 500 login events.")