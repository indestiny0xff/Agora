import feedparser
from termcolor import colored
import argparse
from datetime import datetime
import requests
import re
import json

agora_ascii_art = """
   ,---.           _,---.      _,.---._                    ,---.      
 .--.'  \\      _.='.'-,  \\   ,-.' , -  `.    .-.,.---.   .--.'  \\     
 \\==\\-/\\ \\    /==.'-     /  /==/_,  ,  - \\  /==/  `   \\  \\==\\-/\\ \\    
 /==/-|_\\ |  /==/ -   .-'  |==|   .=.     ||==|-, .=., | /==/-|_\\ |   
 \\==\\,   - \\ |==|_   /_,-. |==|_ : ;=:  - ||==|   '='  / \\==\\,   - \\  
 /==/ -   ,| |==|  , \\_.' )|==| , '='     ||==|- ,   .'  /==/ -   ,|  
/==/-  /\\ - \\\\==\\-  ,    (  \\==\\ -    ,_ / |==|_  . ,'. /==/-  /\\ - \\ 
\\==\\ _.=\\.-' /==/ _  ,  /   '.='. -   .'  /==/  /\\ ,  )\\==\\ _.=\\.-' 
 `--`         `--`------'      `--`--''    `--`-`--`--'  `--`         
"""

news_feeds = {
    "Therecordmedia": "https://therecord.media/feed",
    "TheCyberExpress": "https://thecyberexpress.com/feed/",
    "Securityaffairs": "https://securityaffairs.com/feed",
    "Securityweek": "https://www.securityweek.com/feed/",
    "TheHackerNews": "https://feeds.feedburner.com/TheHackersNews",
    "Sentinelone": "https://fr.sentinelone.com/blog/feed/",
    "Threatpost": "https://threatpost.com/feed",
    "KrebsOnSecurity": "https://krebsonsecurity.com/feed/", 
    "Microsoft": "https://www.microsoft.com/en-us/security/blog/feed/",
    "Microsoftthreathunting": "https://msrc.microsoft.com/blog/categories/microsoft-threat-hunting/feed",
    "Itguru": "https://www.itsecurityguru.org/feed/",
    "Amazon": "https://aws.amazon.com/fr/blogs/security/feed/",
    "Sophos": "https://news.sophos.com/en-us/category/threat-research/feed/",
    "GrahamCluley": "https://grahamcluley.com/feed/",
    "Decoded": "https://decoded.avast.io/feed/",
    "Dataprivacy": "https://www.dataprivacyandsecurityinsider.com/feed/",
    "SecurityBoulevard": "https://securityboulevard.com/feed/",
    "Socprime": "https://socprime.com/blog/feed/",
    "Intel471": "https://intel471.com/blog/feed/",
    "Crowdstrike": "https://www.crowdstrike.com/blog/category/threat-intel-research/feed/",
    "Hackread": "https://www.hackread.com/feed/",
    "Infoblox": "https://blogs.infoblox.com/category/cyber-threat-intelligence/feed/",
    "Zerofox": "https://www.zerofox.com/blog/feed/",
    "Ransomware": "https://ransomware.org/feed/",
    "Helpnetsecurity": "https://www.helpnetsecurity.com/feed/",
    "Coveware": "https://www.coveware.com/blog?format=RSS",
    "BleepingComputer" : "https://www.bleepingcomputer.com/feed/",
    "Seqwrite": "https://www.seqrite.com/blog/tag/ransomware/feed/",
    "Hkcert": "https://www.hkcert.org/getrss/security-bulletin",
    "Enisa": "https://www.enisa.europa.eu/atom.xml",
    "Securityboulevard": "https://securityboulevard.com/feed/"
}   

cve_feeds = {
    "cisa": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
}

leak_feeds = {
    "Leak-lookup": "https://leak-lookup.com/rss",
    "Breach-feed": "https://www.upguard.com/breaches/rss.xml",
    "Databreaches": "https://databreaches.net/feed/",
    "Haveibeenpwned": "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches"
}

ransom_feeds = {
    "Ransomwarelive": "https://ransomware.live/rss.xml",
    "Redpacket": "https://www.redpacketsecurity.com/feed/",
    "Ransomlookup": "https://www.ransomlook.io/rss.xml"
}
osint_feeds = {
   "Belligcat": "https://www.bellingcat.com/feed",
   "Citizenlabs": "https://citizenlab.ca/feed/",
   "Inteltechniques": "https://inteltechniques.com/blog/feed/",
   "Authentic8": "https://www.authentic8.com/rss.xml",
   "Exposingtheinvisible": "https://exposingtheinvisible.org/rss.xml",
   "Skopenow": "https://www.skopenow.com/news/rss.xml",
   "Geoint": "https://geoint.blog/feed/",
   "Osintcombine": "https://www.osintcombine.com/blog-feed.xml",
   "Bushidotoken": "https://blog.bushidotoken.net/",
   "RedditOSINT": "https://www.reddit.com/r/OSINT/new.rss"
}

threat_intel_feeds = {
    "Sucuri": "https://blog.sucuri.net/feed",
    "Ecleticiq": "https://blog.eclecticiq.com/rss.xml",
    "Proofpoint": "https://www.proofpoint.com/us/rss.xml",
    "Silentpush": "https://www.silentpush.com/feed/",
    "Securityscorecard": "https://securityscorecard.com/feed/",
    "Welivesecurity": "https://www.welivesecurity.com/feed",
    "Falconforce": "https://falconforce.nl/feed/",
    "Redcanary": "https://redcanary.com/feed",
    "Cybereason": "https://www.cybereason.com/blog/rss.xml",
    "Cybergeek": "https://cybergeeks.tech/feed/",
    "Purpl3f0xsecur1ty": "https://www.purpl3f0xsecur1ty.tech/feed",
    "Harfanglab": "https://harfanglab.io/en/insidethelab/feed/",
    "Kelacyber": "https://www.kelacyber.com/feed/",
    "Malwarebytes": "https://www.malwarebytes.com/blog/feed/index.xml",
    "Rapid7": "https://blog.rapid7.com/rss/",
    "Asec": "https://asec.ahnlab.com/en/feed/",
    "Imperva": "https://www.imperva.com/blog/feed/",
    "Russianpanda": "https://russianpanda.com/feed.xml",
    "Chomp": "https://chomp.ie/rss.xml",
    "Elastic": "https://www.elastic.co/security-labs/rss/feed.xml",
    "Resecurity": "https://www.resecurity.com/feed",
    "Trustwave": "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rss.xml",
    "Flashpoint": "https://flashpoint.io/feed",
    "Secureblink": "https://www.secureblink.com/rss-feeds/threat-research",
    "Assetnote": "https://blog.assetnote.io/feed.xml",
    "Talos": "https://blog.talosintelligence.com/rss/",
    "Securelist": "https://securelist.com/feed/",
    "Thedefirreport" : "https://thedfirreport.com/feed/",
    "Sensepost": "https://sensepost.com/rss.xml",
    "Spectrops": "https://posts.specterops.io/feed",
    "Trendmicro": "http://feeds.trendmicro.com/TrendMicroSimplySecurity",
    "Unit42": "http://researchcenter.paloaltonetworks.com/unit42/feed/",
    "Phishlabs": "http://blog.phishlabs.com/rss.xml",
    "Virusbulletin": "https://www.virusbulletin.com/rss",
    "Morphisec": "https://blog.morphisec.com/rss.xml",
    "Labsnettitude": "https://labs.nettitude.com/feed/",
    "Deppendresearch": "http://www.deependresearch.org/rss.xml",
    "Secplicity": "https://www.secplicity.org/feed/",
    "IntergoMac": "https://www.intego.com/mac-security-blog",
    "Blackkite": "https://blackkite.com/feed/",
    "Phoenixsecurity": "https://phoenix.security/feed/",
    "Veloxity": "https://www.volexity.com/feed",
    "Catonetworks": "https://www.catonetworks.com/feed/",
    "Watchtowr": "https://labs.watchtowr.com/rss/",
    "Intrinsec": "https://www.intrinsec.com/feed/",
    "Sekoia": "https://blog.sekoia.io/feed/",
    "Risky": "https://news.risky.biz/rss/"
}

disinfo_feeds = {
    "Lawfarmedia": "https://www.lawfaremedia.org/feeds/cybersecurity-tech",
    "Cybercom.mil": "https://www.cybercom.mil/DesktopModules/ArticleCS/RSS.ashx?ContentType=1&Site=848&isdashboardselected=0&max=20",
    "USDepartment": "https://2021-2025.state.gov/feed/",
    "Internationalaffairs": "https://www.internationalaffairs.org.au/feed",
    "Aljazeera": "https://www.aljazeera.com/xml/rss/all.xml",
    "Rferl": "https://www.rferl.org/api/",
    "Europeanwesternbalkans": "https://europeanwesternbalkans.com/feed/"
}

def display_filtered_feed(rss_url, keyword, start_date=None, end_date=None, verbose=False, json_output=False, page_size=10):
    try:
        feed = feedparser.parse(rss_url)
        entries = []
        for entry in feed.entries:
            title = entry.title if 'title' in entry else 'unknown title'
            description = entry.description if 'description' in entry else 'unknown description'
            author = entry.author if 'author' in entry else 'unknown author'
            date = entry.published if 'published' in entry else 'unknown date'
            link = entry.link if 'link' in entry else 'unknown link'

            date_match = re.search(r'\d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2}', date)
            if date_match:
                date = date_match.group(0)
                entry_date = datetime.strptime(date, "%d %b %Y %H:%M:%S")
            else:
                # Handle case where date doesn't match expected format
                entry_date = None  # or some default date handling logic

            if (not keyword or
                keyword.lower() in title.lower() or
                keyword.lower() in description.lower()):
                if start_date is None or (entry_date and entry_date >= start_date):
                    if end_date is None or (entry_date and entry_date <= end_date):
                        entries.append({
                            "title": title,
                            "description": description,
                            "author": author,
                            "date": date,
                            "link": link
                        })

        if json_output:
            return entries

        total_pages = (len(entries) + page_size - 1) // page_size
        current_page = 0
        while current_page < total_pages:
            for i in range(current_page * page_size, min((current_page + 1) * page_size, len(entries))):
                entry = entries[i]
                print("Title:", entry['title'])
                if verbose:
                    print("Description:", entry['description'])
                print("Author:", entry['author'])
                print("Date:", entry['date'])
                print("Link:", entry['link'])
                print()

            if current_page < total_pages - 1:
                user_input = input("Press <Enter> to view next page: ")
                if user_input.lower() != " ":
                    break
            current_page += 1

    except Exception as e:
        print(f"An error occurred: {e}")

def display_filtered_json(json_url, keyword=None, start_date=None, end_date=None, verbose=False, json_output=False, page_size=10):
    try:
        data = requests.get(json_url).json()
        vulnerabilities = []

        for vulnerability in data['vulnerabilities']:
            cve_id = vulnerability.get('cveID')
            vulnerability_name = vulnerability.get('vulnerabilityName')
            date_added = vulnerability.get('dateAdded')
            description = vulnerability.get('shortDescription')

            if (not keyword or
                keyword.lower() in cve_id.lower() or
                keyword.lower() in vulnerability_name.lower() or
                keyword.lower() in description.lower()):

                if date_added:
                    date_added = datetime.strptime(date_added, "%Y-%m-%d")

                if (start_date is None or date_added >= start_date) and \
                        (end_date is None or date_added <= end_date):
                    vulnerabilities.append({
                        "cve_id": cve_id,
                        "vulnerability_name": vulnerability_name,
                        "date_added": date_added.strftime("%Y-%m-%d") if date_added else "",
                        "description": description
                    })
                           
            if json_output:
               return vulnerabilities

        total_pages = (len(vulnerabilities) + page_size - 1) // page_size
        current_page = 0
        while current_page < total_pages:
            for i in range(current_page * page_size, min((current_page + 1) * page_size, len(vulnerabilities))):
                vulnerability = vulnerabilities[i]
                print("CVE ID:", vulnerability['cve_id'])
                print("Vulnerability Name:", vulnerability['vulnerability_name'])
                print("Date Added:", vulnerability['date_added'])
                if verbose:
                    print("Description:", vulnerability['description'])
                print()

            if current_page < total_pages - 1:
                user_input = input("Press <Enter> to view next page:")
                if user_input.lower() != " ":
                    break
            current_page += 1

    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="AGORA: Fetch and display information about cybersecurity news from various sources including articles, CVEs, ransomware attacks, and leaks, with filtering by keyword and date.")
    parser.add_argument("--argument",choices=["news","cve","leak","ransom","threat_intel","osint","disinfo"],help="choose between news, cve and leak")
    parser.add_argument("--verbose",help="For more details",action="store_true")
    parser.add_argument("--keyword", default="", help="Filter by keyword in the title")
    parser.add_argument("--start-date", help="Filter from this date (in 'YYYY-MM-DD' format)")
    parser.add_argument("--end-date", help="Filter until this date (in 'YYYY-MM-DD' format)")
    parser.add_argument("--json", metavar='FILENAME', help="Output results to a JSON file")
    parser.add_argument("-help", action="help", help="Display help message")

    args = parser.parse_args()


    if not args.argument:
        print(agora_ascii_art)
        parser.print_help()
        return

    print(agora_ascii_art)

    results = []
    
    if args.json:
        filename = args.json


    if args.argument == "news":
        news_sources = news_feeds.keys()
        for source in news_sources:
            news_url = news_feeds[source]
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else None
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else None
            if args.keyword:
                print(colored(f"📰 Results from news source '{source}' with the keyword '{args.keyword}':", "blue"))
                source_results = display_filtered_feed(news_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            else:
                print(colored(f"📰 Results from news source '{source}':", "blue"))
                source_results = display_filtered_feed(news_url, None, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            if args.json and source_results:
                results.extend(source_results)

    if args.argument == "cve":
        cve_sources = cve_feeds.keys()
        for source in cve_sources:
            cve_url = cve_feeds[source]
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else None
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else None
            if args.keyword:
                print(colored(f"💣 Results from CVE source '{source}' with the keyword '{args.keyword}':", "red"))
                source_results = display_filtered_json(cve_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            else:
                print(colored(f"💣 Results from CVE source '{source}':", "red"))
                source_results = display_filtered_json(cve_url, None, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            if args.json and source_results:
                results.extend(source_results)

    if args.argument == "leak":
        leak_sources = leak_feeds.keys()
        for source in leak_sources:
            leak_url = leak_feeds[source]
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else None
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else None
            if args.keyword:
                print(colored(f"🕵️ Results from leak source '{source}' with the keyword '{args.keyword}':", "green"))
                source_results = display_filtered_feed(leak_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            else:
                print(colored(f"🕵️ Results from leak source '{source}':", "green"))
                source_results = display_filtered_feed(leak_url, None, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            if args.json and source_results:
                results.extend(source_results)

    if args.argument == "ransom":
        ransom_sources = ransom_feeds.keys()
        for source in ransom_sources:
            ransom_url = ransom_feeds[source]
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else None
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else None
            if args.keyword:
                print(colored(f"🔒 Results from ransom source '{source}' with the keyword '{args.keyword}':", "yellow"))
                source_results = display_filtered_feed(ransom_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            else:
                print(colored(f"🔒 Results from ransom source '{source}':", "yellow"))
                source_results = display_filtered_feed(ransom_url, None, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            if args.json and source_results:
                results.extend(source_results)

    if args.argument == "threat_intel":
        threat_intel_sources = threat_intel_feeds.keys()
        for source in threat_intel_sources:
            threat_intel_url = threat_intel_feeds[source]
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else None
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else None
            if args.keyword:
                print(colored(f"💿 Results from threat intel source '{source}' with the keyword '{args.keyword}':", "magenta"))
                source_results = display_filtered_feed(threat_intel_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            else:
                print(colored(f"💿 Results from threat intel source '{source}':", "magenta"))
                source_results = display_filtered_feed(threat_intel_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            if args.json and source_results:
                results.extend(source_results)

    if args.argument == "osint":
        osint_sources = osint_feeds.keys()
        for source in osint_sources:
            osint_url = osint_feeds[source]
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else None
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else None
            if args.keyword:
                print(colored(f"💀 Results from OSINT source '{source}' with the keyword '{args.keyword}':", "cyan"))
                source_results = display_filtered_feed(osint_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            else:
                print(colored(f"💀 Results from OSINT source '{source}':", "cyan"))
                source_results = display_filtered_feed(osint_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            if args.json and source_results:
                results.extend(source_results)
               
    if args.argument == "disinfo":
        disinfo_sources = disinfo_feeds.keys()
        for source in disinfo_sources:
            disinfo_url = disinfo_feeds[source]
            start_date = datetime.strptime(args.start_date, "%Y-%m-%d") if args.start_date else None
            end_date = datetime.strptime(args.end_date, "%Y-%m-%d") if args.end_date else None
            if args.keyword:
                print(colored(f"⚠️📰 Results from Disinfo source '{source}' with the keyword '{args.keyword}':", "light_blue"))
                source_results = display_filtered_feed(disinfo_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            else:
                print(colored(f"⚠️📰 Results from Disinfo source '{source}':", "light_blue"))
                source_results = display_filtered_feed(disinfo_url, args.keyword, start_date, end_date, verbose=args.verbose, json_output=args.json)
                print()
            if args.json and source_results:
                results.extend(source_results)
               

    if args.json and results:
        with open(f'{filename}.json', 'w') as json_file:
            json.dump(results, json_file, indent=4)

if __name__ == "__main__":
    print()
    main()  





