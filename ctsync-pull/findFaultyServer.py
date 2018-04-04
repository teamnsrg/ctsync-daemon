import json
with open("dbout.txt") as f:
    content = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
content = [x.strip() for x in content]
workingservers = {}
for line in content:
    entries = line.split('|') 
    workingservers[entries[-2]] = 0

with open("fullConfig.json") as f:
    content = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
content = [x.strip() for x in content]
outstring = ""
for line in content:
    d = json.loads(line)
    if d["url"] not in workingservers.keys():
        outstring += d["url"] + '\n'

text_file = open("FaultyServers.txt", "w")
text_file.write(outstring)
text_file.close()