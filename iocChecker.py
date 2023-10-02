import requests
import json
from requests_toolbelt.multipart.encoder import MultipartEncoder
import argparse
import sys 
import platform
import base64
######### Check Arguments
sistema = format(platform.system())

if (sistema == "Linux"):
	# Text colors
	normal_color = "\33[00m"
	info_color = "\033[1;33m"
	red_color = "\033[1;31m"
	green_color = "\033[1;32m"
	whiteB_color = "\033[1;37m"
	detect_color = "\033[1;34m"
	banner_color="\033[1;33;40m"
	end_banner_color="\33[00m"
elif (sistema == "Windows"):
	normal_color = ""
	info_color = ""
	red_color = ""
	green_color = ""
	whiteB_color = ""
	detect_color = ""
	banner_color=""
	end_banner_color=""

def banner():

    print (banner_color + "                                                               ('-. .-.   ('-.             .-. .-')     ('-.  _  .-')   " + end_banner_color) 
    print (banner_color + "                                                              ( OO )  / _(  OO)            \  ( OO )  _(  OO)( \( -O )  " + end_banner_color)
    print (banner_color + "     ,--.   .-----.  ,-.-')  .-'),-----.    .-----.   .-----. ,--. ,--.(,------.   .-----. ,--. ,--. (,------.,------.  " + end_banner_color)
    print (banner_color + " .-')| ,|  '  .--./  |  |OO)( OO'  .-.  '  '  .--./  '  .--./ |  | |  | |  .---'  '  .--./ |  .'   /  |  .---'|   /`. ' " + end_banner_color)
    print (banner_color + "( OO |(_|  |  |('-.  |  |  \/   |  | |  |  |  |('-.  |  |('-. |   .|  | |  |      |  |('-. |      /,  |  |    |  /  | | " + end_banner_color)
    print (banner_color + "| `-'|  | /_) |OO  ) |  |(_/\_) |  |\|  | /_) |OO  )/_) |OO  )|       |(|  '--.  /_) |OO  )|     ' _)(|  '--. |  |_.' | "+ end_banner_color)
    print (banner_color + ",--. |  | ||  |`-'| ,|  |_.'  \ |  | |  | ||  |`-'| ||  |`-'| |  .-.  | |  .--'  ||  |`-'| |  .   \   |  .--' |  .  '.' " + end_banner_color) 
    print (banner_color + "|  '-'  /(_'  '--'\(_|  |      `'  '-'  '(_'  '--'\(_'  '--'\ |  | |  | |  `---.(_'  '--'\ |  |\   \  |  `---.|  |\  \  " + end_banner_color)
    print (banner_color + "  `-----'    `-----'  `--'        `-----'    `-----'   `-----' `--' `--' `------'   `-----' `--' '--'  `------'`--' '--' " + end_banner_color)
    print (" ")
    print (" ")


def checkArgs():
	parser = argparse.ArgumentParser()
	parser = argparse.ArgumentParser(description='MobSF IOC Extractor 1.0\n')

	parser.add_argument('-f', "--file", action="store",
						dest='file',
						help="File to upload & analize un MobSF")

	args = parser.parse_args()
	if (len(sys.argv)==1) or (args.file==False):
		parser.print_help(sys.stderr)
		sys.exit(1)
	return args

def upload_file(api_key, file_path):
    url = "http://172.17.0.2:8000/api/v1/upload"
    headers = {"Authorization": api_key}

    multipart_data = MultipartEncoder(fields={'file': (file_path, open(file_path, 'rb'), 'application/octet-stream')})
    headers = {'Content-Type': multipart_data.content_type, 'Authorization': api_key}
    response = requests.post(url, data=multipart_data, headers=headers)
    
    return response.text

def scan(api_key,data):
 
    post_dict = json.loads(data)
    url = "http://172.17.0.2:8000/api/v1/scan"
    headers = {'Authorization': api_key}
    response = requests.post(url, data=post_dict, headers=headers)
    

def getReportJson(api_key,data,vtApi_key):
    post_dict = json.loads(data)
    url = "http://172.17.0.2:8000/api/v1/report_json"
    headers = {'Authorization': api_key}
    response = requests.post(url, data=post_dict, headers=headers)

    respuesta = json.loads(response.text)

    data = respuesta["urls"]
    all_urls = []
    for item in data:
        urls_list = item.get('urls', [])  
        all_urls.extend(urls_list)       

    unique_urls = list(set(all_urls))
    for url in unique_urls:
        print (url)


    data = respuesta["domains"]
    all_ips = []
    for domain, info in data.items():
        geolocation = info.get('geolocation')
        if geolocation:
            ip = geolocation.get('ip')
            if ip:
                all_ips.append(ip)

    unique_ips = list(set(all_ips))
    
    vtHeaders = {"accept": "application/json",
    "x-apikey": vtApi_key}
    print("\r\nshowing possible malicious url info\r\n")
    for domains in unique_urls:
        print(domains)
        vtUrl = "https://www.virustotal.com/api/v3/urls/"
        url_id = base64.urlsafe_b64encode(domains.encode()).decode().strip("=")
        print(url_id)
        vtUrl = vtUrl + url_id
        response = requests.get(vtUrl,headers=vtHeaders)
        
        urlDataResult = json.loads(response.text)
        print(urlDataResult["data"]["attributes"]["last_analysis_stats"])
        #print(response.text)
        print("\n\n")
        #cargar la info que nos interese json.loads(response.text)
    
    print("\r\nshowing possible malicious ip info\r\n")
    print(unique_ips)
    for urls in unique_ips:
        print(urls)
        vtUrl = "https://www.virustotal.com/api/v3/ip_addresses/"
        
        print(url_id)
        vtUrl = vtUrl + urls
        response = requests.get(vtUrl,headers=vtHeaders)
        
        urlDataResult = json.loads(response.text)
        print(urlDataResult["data"]["attributes"]["last_analysis_stats"])
        #print(response.text)
        print("\n\n")
   

if __name__ == "__main__":
    banner()
    args = checkArgs()
    
    if (args.file):
        api_key = "INSERT MOBSF APIKEY HERE"
        vtApi_key = "INSERT VIRUSTOTAL APIKE HERE"
        
        file_path = args.file
        
        upload_data = upload_file(api_key, file_path)
        scan(api_key,upload_data)
        getReportJson(api_key, upload_data,vtApi_key)
