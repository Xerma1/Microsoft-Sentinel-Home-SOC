# Microsoft-Sentinel-SOC-map

I created a heatmap in Microsoft Azure using Microsoft Sentinel SIEM tool, here is how it was done.

## Overall structure
<img width="1475" height="815" alt="image" src="https://github.com/user-attachments/assets/e6e201c6-e7c6-479d-ade5-3694511fdf4f" />


## Create resource group

In microsoft azure, create a resource group, which will act as a "folder" that organizes all of the resources we will be creating together. It makes it easier to track costs as well as bulk deleting them when I am done with the lab

<img width="1240" height="711" alt="image" src="https://github.com/user-attachments/assets/e2c91d7e-b65f-4729-995b-5098d9635f05" />

## Create virtual network

Next, set up a virtual network under the resource group that was just created.

<img width="1236" height="885" alt="image" src="https://github.com/user-attachments/assets/d4e16bef-e382-47fa-8dab-94f849e39016" />

## Create your Honeypot virtual machine

Next, create your virtual machine, again under the same resource group.
<img width="1232" height="1220" alt="image" src="https://github.com/user-attachments/assets/5264532d-6d3a-4fe1-a4e0-10c77a0018e2" />

## Configure virtual network and virtual machine firewall
First, go to your resource group, and select the network security group resource.
<img width="2264" height="1259" alt="image" src="https://github.com/user-attachments/assets/cf61beed-3bc3-48ea-846a-19a7aa45fb06" />

Under inbound security rules, delete any current security rules, and then add a new one.
<img width="2526" height="1033" alt="image" src="https://github.com/user-attachments/assets/f5deedcc-eb2d-48e1-9334-9fb59389708f" />

Set the rule to this:
<img width="886" height="1312" alt="image" src="https://github.com/user-attachments/assets/7e4dcef4-fe15-4fdf-a847-52ad2143ef59" />
 This will allow any inbound connection through, which is what we want for our honey pot.</br>

Then, RDP into your virtual machine, and go into Windows Defender Firewall. Disable all firewalls (under the Windows Defender Firewall Properties)
<img width="1070" height="783" alt="image" src="https://github.com/user-attachments/assets/24396751-c4a5-4fe7-bc52-a7f2c220c7c7" />
Nice! We now have a honeypot that allows all connections through! In Event Viewer, filter the EventID to "4625" (login failure) to start seeing real adversaries trying to access your VM.

## Create log analytics workspaces
Next, create a log analytics workspaces that will hold your event logs
<img width="1250" height="566" alt="image" src="https://github.com/user-attachments/assets/ada98e7d-3cae-4510-9952-cd0cfd4f4303" />

Connect it to Sentinel!
<img width="1259" height="524" alt="image" src="https://github.com/user-attachments/assets/68df7448-aacc-41e6-acc8-6ba5e2f214b6" />
Select the workspace that you just created, and Azure will add Sentinel to it.

Now, we have to link the workspace to our virtual machine to start populating it with data. Select your Sentinel, go to Content Management > Content hub, search for windows security events, and install it. After it installs, click manage, and then select windows security events via AMA > open connector page > create data collection rule and we should be able to see it in our VM under Extenstions.

<img width="2512" height="1057" alt="image" src="https://github.com/user-attachments/assets/67b61228-9cd9-4f1e-bd65-b8debd287623" />

## See your log analytics workspace start being populated!

<img width="2535" height="1306" alt="image" src="https://github.com/user-attachments/assets/55253669-440b-4240-98af-7cf1c76a9165" />

Observe the SecurityEvent logs in the Log Analytics Workspace; there is no location data, only IP address, which we can use to derive the location data.

## Creating the heatmap

We are going to import a spreadsheet (as a “Sentinel Watchlist”) which contains geographic information for each block of IP addresses.

Download: [geoip-summarized.csv](https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view) 

Within Sentinel, create the watchlist:

Name/Alias: geoip
Source type: Local File (the csv file)
Number of lines before row: 0
Search Key: network

Allow the watchlist to fully import, there should be a total of roughly 54,000 rows.

In real life, this location data would come from a live source or it would be updated automatically on the back end by your service provider.

Observe the logs now have geographic information, so you can see where the attacks are coming from

```let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == <attacker IP address>
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

Within Sentinel, create a new Workbook

<img width="1485" height="901" alt="image" src="https://github.com/user-attachments/assets/5e648133-6e25-478a-8d55-eea476102224" />

Delete the prepopulated elements and add a “Query” element

Go to the advanced editor tab, and paste the JSON:

```
{
	"type": 3,
	"content": {
	"version": "KqlItem/1.0",
	"query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents = SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp = IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location = strcat(cityname, \" (\", countryname, \")\");",
	"size": 3,
	"timeContext": {
		"durationMs": 2592000000
	},
	"queryType": 0,
	"resourceType": "microsoft.operationalinsights/workspaces",
	"visualization": "map",
	"mapSettings": {
		"locInfo": "LatLong",
		"locInfoColumn": "countryname",
		"latitude": "latitude",
		"longitude": "longitude",
		"sizeSettings": "FailureCount",
		"sizeAggregation": "Sum",
		"opacity": 0.8,
		"labelSettings": "friendly_location",
		"legendMetric": "FailureCount",
		"legendAggregation": "Sum",
		"itemColorSettings": {
		"nodeColorField": "FailureCount",
		"colorAggregation": "Sum",
		"type": "heatmap",
		"heatmapPalette": "greenRed"
		}
	}
	},
	"name": "query - 0"
}
```

Finished!

<img width="1735" height="1062" alt="image" src="https://github.com/user-attachments/assets/c1cc2da2-3539-4d5b-9a80-f8f620752d09" />

This is the amount of ppl trying to gain access into my honeypot in just 3 hours... insane
