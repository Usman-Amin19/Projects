import requests

API_TOKEN = 'YOUR_API_KEY_FROM_COC_DEVELOPERS_PORTAL'
CLAN_TAG = '#29VCPLRRY'

# URL encode the clan tag if needed
encoded_clan_tag = CLAN_TAG.replace('#', '%23')

# Access Clan Members
url = f"https://api.clashofclans.com/v1/clans/{encoded_clan_tag}/members"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json"
}

# Make the request
response = requests.get(url, headers=headers)

current_clan_members = []

if response.status_code == 200:
    data = response.json()
    for member in data['items']:
        current_clan_members.append({'tag' : member['tag'], 'name': member['name']})
else:
    print(f"Error: {response.status_code}")
    print(response.text)

# Access Capital Raids Data
url = f"https://api.clashofclans.com/v1/clans/{encoded_clan_tag}/capitalraidseasons"

# Make the request
response = requests.get(url, headers=headers)

raids = []

if response.status_code == 200:
    data = response.json()
    raids = data['items'][0]
else:
    print(f"Error: {response.status_code}")
    print(response.text)

raids_done = raids['members']

print("Total number of members who participated in raid weekend:", len(raids_done))
print('\n', end='')

print("Raids not completed by:- ")
for member in raids_done:
    if member['attacks'] < member['attackLimit'] + member['bonusAttackLimit']:
        print(f"{member['name']} - {member['attacks']} / {member['attackLimit'] + member['bonusAttackLimit']}")

print('\n', end='')
print("Raids not done by:- ")
for mem in current_clan_members:
    if mem['tag'] not in [member['tag'] for member in raids_done]:
        print(mem['name'])
