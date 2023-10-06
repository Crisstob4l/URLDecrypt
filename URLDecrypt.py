import argparse
import requests
import subprocess 
import json       
import time
import datetime
from colorama import Fore,Style,init    
import sys 
API_KEY = 'YOUR API KEY'
API_SCAN = 'https://www.virustotal.com/api/v3/urls'

def banner():
    ascii_art = '''
 ██╗   ██╗██████╗ ██╗     ██████╗ ███████╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
 ██║   ██║██╔══██╗██║     ██╔══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
 ██║   ██║██████╔╝██║     ██║  ██║█████╗  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
 ██║   ██║██╔══██╗██║     ██║  ██║██╔══╝  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
 ╚██████╔╝██║  ██║███████╗██████╔╝███████╗╚██████╗██║  ██║   ██║   ██║        ██║   
 ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
   
                                                                    By:4ntrx
 '''
    print(Fore.LIGHTYELLOW_EX,"\t",ascii_art, Style.RESET_ALL)


def Expand(url):
    try:
        respon = requests.head(url, allow_redirects=True)
        urlOriginal = respon.url
        return urlOriginal
    except requests.exceptions.RequestException as error:
        print(Fore.RED + "[+] ERROR -> "+ Style.RESET_ALL, error)
        return None

def Requirements():
    units = ['requests', 'colorama']

    for unit in units:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', unit])

def Scan(target_url):

    payload = { "url": target_url }
    headers = {
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
    "x-apikey": API_KEY
    }
    response = requests.post(API_SCAN, data=payload, headers=headers)
    data = response.json()
    analysis_id = data['data']['id']
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        response = requests.get(analysis_url, headers=headers)
        data = response.json()

        if data['data']['attributes']['status'] == 'completed':
            break
        time.sleep(5)

    attributes = data['data']['attributes']
    date = datetime.datetime.fromtimestamp(attributes['date'])
    formatted_date = date.strftime("%d/%m/%Y")
    print(Fore.LIGHTCYAN_EX + f"\tDATE -> {Style.RESET_ALL}{formatted_date}")
    print("")
    print(Fore.LIGHTCYAN_EX+f"\tSTATUS ->  {Style.RESET_ALL}{attributes['status']}")
    print("")
    print(Fore.RED + f"\tMALICIUS ->  {Style.RESET_ALL}{attributes['stats']['malicious']}")
    print("")
    print(Fore.RED + f"\tSUSPICIUS -> {Style.RESET_ALL}{attributes['stats']['suspicious']}")

    if attributes['stats']['malicious'] > 0 or attributes['stats']['suspicious']:
        print("")
        print(Fore.LIGHTRED_EX+ f"\t\t\u26A0 W A R N I N G -> {Style.RESET_ALL}{Fore.LIGHTWHITE_EX} URL DETECTED AS MALICIOUS{Style.RESET_ALL} ")
    else:
        print("")
        print(Fore.LIGHTCYAN_EX + f"\t\t\u2714 -> ALL GOOD WITH THE URL{Style.RESET_ALL}")

def main():
     parser = argparse.ArgumentParser()
     parser.add_argument('-d', '--download', action='store_true', help='Download of required resources')
     parser.add_argument('url', nargs='?', default=None, help='URL to scanner')

     arr = parser.parse_args()

     if arr.download:
         banner()
         print(Fore.YELLOW + "\t[+] Downloading necessary packages..."+ Style.RESET_ALL)
         Requirements()
     elif arr.url:
         banner()
         print(Fore.LIGHTBLUE_EX+ f"\t[+] URL provided -> {Style.RESET_ALL    }{arr.url}")
         print("")
         expanded = Expand(arr.url)
         print(Fore.LIGHTGREEN_EX + f"\t[+] Original URL -> {Style.RESET_ALL} {expanded}")
         print("")
         print(Fore.LIGHTWHITE_EX + "******************************   STARTING SCAN   ******************************" + Style.RESET_ALL)
         print("")
         Scan(expanded)
         print("")
         print("")
         print("")
         print("")
     else:
         banner()
         print(Fore.YELLOW + "\tpy URLDecrypt + -d -> Resource download" + Style.RESET_ALL)
         print(Fore.YELLOW + "\tpy URLDecrypt + URL -> Scanning" + Style.RESET_ALL)
         
if __name__ == "__main__":
    main()
