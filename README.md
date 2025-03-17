# AGORA - Your Cybersecurity Info Companion! 🛡️🌐

Welcome to AGORA, your one-stop destination for all things cybersecurity! 🚀

## What Does AGORA Offer?

- **News Galore! 📰**: Dive into the latest cybersecurity news from renowned sources like TheHackerNews, Threatpost, KrebsOnSecurity, and many more!
  
- **CVEs at Your Fingertips! 💣**: Stay informed about Common Vulnerabilities and Exposures (CVEs) from authoritative sources such as CISA.
  
- **Leak Investigations! 🕵️**: Explore data breaches and leaks with ease, thanks to AGORA's comprehensive coverage from various leak databases.
  
- **Ransomware Radar! 🔒**: Keep a keen eye on ransomware attacks reported by sources like Ransomwarelive, Redpacket, and more.

- **Threat Intelligence! 🔍**: Get insights into the latest threat intelligence to stay ahead of emerging threats.

- **Open Source Intelligence (OSINT)! 🧠**: Access a wealth of OSINT articles to enhance your understanding of current cyber threats and trends.

- **Disinformation Watch! 🏴‍☠️**: Track and analyze disinformation campaigns, propaganda tactics, and misinformation trends from credible sources to stay informed and vigilant.

## How to Use AGORA?

AGORA is user-friendly and straightforward! Simply run the program with a few command-line arguments to access a wealth of cybersecurity information. Here's a sneak peek:

### Example 1: Fetch Cybersecurity News
```bash
python Agora.py --argument news --keyword "Sandworm" --start-date "2023-01-01" 
```
### Example 2: Explore CVEs

```bash
python Agora.py --argument cve --keyword "Fortinet" --start-date "2023-01-01" 
```

This command will display CVEs related to exploits reported in 2023 with detailed descriptions.

### Example 3: Investigate Leaks

```bash
python Agora.py --argument leak --start-date "2023-01-01" 
```

This command will provide information about data breaches and leaks reported in 2023 with verbose descriptions.  

### Example 4: Monitor Ransomware

```bash
python Agora.py --argument ransom --keyword "LockBit" --start-date "2023-01-01" 
```

This command will show ransomware attacks involving the LockBit variant reported in 2023 with detailed information.  

### Example 5: Monitor Threat intel

```bash
python Agora.py --argument threat_intel --start-date "2024-01-01" 
```

This command will show threat intel articles. 

### Example 6: Monitor OSINT

```bash
python Agora.py --argument osint --start-date "2024-01-01" 
```

This command will show OSINT articles.

### Example 7: Monitor Disinformation

```bash
python Agora.py --argument disinfo --start-date "2024-01-01" 
```

This command will show disinformation articles.

### Command-Line Arguments

    --argument: Choose between news, cve, leak, ransom, threat_intel,osint, disinfo.
    --keyword: Filter articles by a specific keyword.
    --start-date: Filter starting from this date (YYYY-MM-DD).
    --end-date: Filter until this date (YYYY-MM-DD).
    --verbose: For more detailed information. ( not necessarily useful)


## Installation

To install the required dependencies, simply run:

```bash
git clone https://github.com/WOthm/Agora.git
cd Agora
pip install -r requirements.txt
```
Let AGORA Be Your Cyber Guide!

So, why wait? Let AGORA be your cyber guide in this vast digital wilderness.

Happy Exploring with AGORA! 🚀🔍



