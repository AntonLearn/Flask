import requests
from settings import URL_USER, URL_ADV

# response = requests.post(url=f'{URL_USER}/',
#                         json={'name': 'name_2',
#                               'password': '0987654321'})
# response = requests.post(url=URL_ADV,
#                         headers={'Authorization': '0987654321'},
#                         json={'header': 'header_7',
#                               'owner_id': 2,
#                               'description': 'description_7'})
# response = requests.patch(url=f'{URL_ADV}/7',
#                          headers={'Id': '2', 'Authorization': '0987654321'},
#                          json={'header': 'header_10',
#                                'description': 'description_10'})
response = requests.get(url=f'{URL_ADV}/')
# response = requests.get(url=f'{URL_ADV}/1')
# response = requests.get(url=f'{URL_USER}/3')
# response = requests.get(url=f'{URL_USER}/')
# response = requests.delete(url=f'{URL_USER}/1')
# response = requests.delete(url=f'{URL_ADV}/7',
#                            headers={'Id': '2', 'Authorization': '0987654321'})
# response = requests.patch(url=f'{URL_USER}/2',
#                          json={'name': 'name_2',
#                               'password': '1234567890'})
print(response.status_code)
print(response.json())
