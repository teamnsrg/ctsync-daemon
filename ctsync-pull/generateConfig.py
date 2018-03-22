import json
from collections import OrderedDict
readFileName = "all_logs_list.json"
writeFileName = "fullConfig.json"

readData = json.load(open(readFileName))
logs = readData["logs"]
f= open(writeFileName,"w")
f.close()

for log in logs:
	writeData = OrderedDict()
	nameString = log["description"]
	writeData["name"] = "CT_SERVER_"+nameString.upper().replace(" ","_").replace("'", "")
	writeData["url"] = "https://"+log["url"][:-1]
	writeData["batch_size"] = 1000
	with open(writeFileName, 'a') as outfile:
		json.dump(writeData, outfile)
		outfile.write("\n")
