import json
from datetime import datetime, timedelta

# Load the gift ideas from the JSON file
with open('ideas.json', 'r') as ideas_file:
    gift_ideas_data = json.load(ideas_file)

# Define the threshold for 2 months
two_months_ago = datetime.now() - timedelta(days=20)

# Create a new list to store ideas that should be kept
updated_gift_ideas = []

# Iterate through the gift ideas
for idea in gift_ideas_data:
    # Check if the idea has a 'date_bought' field
    if 'date_bought' in idea:
        # Parse the date_bought field as a datetime object
        date_bought = datetime.strptime(idea['date_bought'], '%Y-%m-%d %H:%M:%S')

        # Check if the date_bought is more than 2 months ago
        if date_bought < two_months_ago:
            # Skip this idea (it has been bought more than 2 months ago)
            continue

    # If the idea is still within the 2-month threshold or doesn't have a 'date_bought' field, add it to the updated list
    updated_gift_ideas.append(idea)

# Save the updated gift ideas back to the JSON file
with open('ideas.json', 'w') as ideas_file:
    json.dump(updated_gift_ideas, ideas_file, indent=2)

print("Ideas older than 2 months have been removed.")
