import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

threshold_days = int(os.getenv("DELETE_DAYS"))  

threshold_time = datetime.now() - timedelta(days=threshold_days)

with open('ideas.json', 'r') as ideas_file:
    gift_ideas_data = json.load(ideas_file)


updated_gift_ideas = []
removed_count = 0

for idea in gift_ideas_data:
    if 'date_bought' in idea:
        date_bought = datetime.strptime(idea['date_bought'], '%Y-%m-%d %H:%M:%S')

        if date_bought < threshold_time:
            removed_count += 1
            continue

    updated_gift_ideas.append(idea)

with open('ideas.json', 'w') as ideas_file:
    json.dump(updated_gift_ideas, ideas_file, indent=2)

last_execution_time = datetime.now().isoformat()
with open('last_execution_time.txt', 'w') as time_file:
    time_file.write(last_execution_time)

print(f"Ideas older than {threshold_days} days have been removed. Total removed: {removed_count}")
