import requests

API_TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6IjI4YTMxOGY3LTAwMDAtYTFlYi03ZmExLTJjNzQ\
zM2M2Y2NhNSJ9.eyJpc3MiOiJzdXBlcmNlbGwiLCJhdWQiOiJzdXBlcmNlbGw6Z2FtZWFwaSIsImp0aSI6ImFhZjIxNGIyLT\
JlOGYtNDM5MS1hMmQ5LTk0Mjc2MDEyOTM5NSIsImlhdCI6MTc1MDE1NjkxMSwic3ViIjoiZGV2ZWxvcGVyLzc1MzQ5NzUxLW\
I5ZjYtM2EyZS04YjEyLTQ4NmMyZTRhODc4ZSIsInNjb3BlcyI6WyJjbGFzaCJdLCJsaW1pdHMiOlt7InRpZXIiOiJkZXZlbG\
9wZXIvc2lsdmVyIiwidHlwZSI6InRocm90dGxpbmcifSx7ImNpZHJzIjpbIjE2Mi4xMi4yMTAuMiJdLCJ0eXBlIjoiY2xpZW\
50In1dfQ.tEsL7Cl47mNTIH84nCPNMNNB7uh_IQf5pTMHDTqynQXpv78NMW_IBqPFFas1teZlGAKcWEBZoxIl9SMMFXpzCQ'
CLAN_TAG = '#29VCPLRRY'

# URL encode the clan tag if needed
encoded_clan_tag = CLAN_TAG.replace('#', '%23')

# API Endpoint
url = f"https://api.clashofclans.com/v1/clans/{encoded_clan_tag}/members"

# HTTP headers
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
        current_clan_members.append(member['name'])
else:
    print(f"Error: {response.status_code}")
    print(response.text)


url = f"https://api.clashofclans.com/v1/clans/{encoded_clan_tag}/capitalraidseasons"

# Make the request
response = requests.get(url, headers=headers)

raids_done = []

if response.status_code == 200:
    data = response.json()
    latest_raid = data['items'][0]
    raids_done = latest_raid['members']
else:
    print(f"Error: {response.status_code}")
    print(response.text)

print(f"Total raids done:", len(raids_done))
print('\n', end='')

print("Raids not completed by:- ")
for member in raids_done:
    if member['attacks'] < member['attackLimit'] + member['bonusAttackLimit']:
        print(f"{member['name']} - {member['attacks']} / {member['attackLimit'] + member['bonusAttackLimit']}")

print('\n', end='')
print("Raids not done by:- ")
for member in current_clan_members:
    if member not in [name for name in (member['name'] for member in raids_done)]:
        print(member)
