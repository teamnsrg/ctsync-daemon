import requests

with open("process.txt") as f:
    content = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
content = [x.strip() for x in content] 
for line in content:
    entries = line.split('|')
    URL = entries[-2] + "/ct/v1/get-sth"
    try:
        r = requests.get(url = URL, params = None)
        data = r.json()
        print str(entries[-2]) + " left: " + str( data["tree_size"] - int(entries[-1]))
    except:
        print str(entries[-2]) + " cannot get tree size "