import json
import re
import sys

# Takes all arguments from command line and, if it detects any json filenames, creates a html for them
for jsonfile in sys.argv:
	if(jsonfile[-5:]==".json"):
		# Takes in the data from the json and converts it to a dictionary
		jsdata = open(jsonfile).read()
		data=json.loads(jsdata)

		# Takes all the scan data and casts it to a list. This means I can iterate through the results and try
		# to figure out which malware is being referenced
		scan = data["scans"]
		results=[]
		for i in scan:
			t = scan[i]["result"]
			results.append(t)

		# Iterates through the list of scan results and picks out keywords
		keyword = []
		for i in range(len(results)):
			if(type(results[i])==str):
				for j in re.sub('\W+',' ', results[i]).split(" "):
					keyword.append(j)

		# Data cleaning
		keyword.sort()
		while "Win32" in keyword:
			keyword.remove("Win32")
		while '' in keyword:
			keyword.remove('')
		while "Trojan" in keyword:
			keyword.remove("Trojan")
			
		# Says that if 15%+ of scans return positive, it's likely to be a virus 
		percent = round(100*data["positives"]/data["total"],0)
		viruschance = percent>15
		if(viruschance):
			conclusion = "Likely a Virus"
		else:
			conclusion = "Likely Safe"
			
		# Putting relevant data into the html
		f = open('%s.html' % jsonfile[:-5],'w')

		message = """
		<html>
			<head>
				<style>
					table {{font-family: arial, sans-serif; border-collapse: collapse; width: 80%;}}
					td,th {{border: 1px solid #dddddd; text-align: left; padding: 8px}}
					tr:nth-child(even) {{background-color: #dddddd}}
				</style>	
			</head>
			<body>
				<table>
					<tt>
						<td colspan=2 bgcolor={0}> <font size="6" color="white"><i>{1}</i></font> </td>
					</tt>
					<tr>
						<th>File Name:</th>					
						<td>{2}</td>
					</tr>
					<tr>
						<th>Size of file:</th>
						<td>{3}KB</td>
					</tr>
					<tr>
						<th> File type:</th>
						<td> {4} </td>
					</tr>
					<tr>
						<th>Date of Scanning:</th> 				
						<td>{5} </td>
					</tr>
					<tr>
						<th>SHA256</th>
						<td>{6} </td>
					</tr>
					<tr>
						<th>MD5</th>
						<td>{7}</td>
					</tr>
					<tr>
						<th>Magic Literal:</th>
						<td>{8}</td>
					<tr>
						<th>Detection Rate:</th>   	
						<td>{9}% ({10}/{11})</td>
					</tr>
					<tr>
						<th>Keyword:</th>
						<th><font size = 5>{12}</font></th> 
					</tr>
				</table>
				<a href="{13}"> Source </a>
			</body>
		</html>""".format(	"red" if viruschance else "green",		#Color of the header on top, red obviously signifying danger					
							conclusion,								#Whether likely to be a virus or not
							data["submission"]["filename"], 		#File Name
							round(data["size"]/1024,2),				#File Size
							data["type"],							#File type
							data["scan_date"],						#Date of the Scan
							data["sha256"],							#SHA256 of the virus
							data["md5"],							#MD5 of the virus
							data["additional_info"]["magic"],		#Magic Literal, usually indicates OS
							percent,								#Percentage of positive scans
							data["positives"],						#Amount of positive scans
							data["total"],							#Total amount of scans
							max(set(keyword),key=keyword.count),	#Most common keyword from the scan results
							data["permalink"])						#Link to the VirusTotal page

		f.write(message)
		f.close()
