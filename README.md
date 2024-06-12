# AGORA - Your Cybersecurity Info Companion! 🛡️🌐

Welcome to AGORA, your one-stop destination for all things cybersecurity! 🚀

## What Does AGORA Offer?

    News Galore! 📰: Dive into the latest cybersecurity news from renowned sources like TheHackerNews, Threatpost, KrebsOnSecurity, and many more!

    CVEs at Your Fingertips! 💣: Stay informed about Common Vulnerabilities and Exposures (CVEs) from authoritative sources such as CISA.

    Leak Investigations! 🕵️: Explore data breaches and leaks with ease, thanks to AGORA's comprehensive coverage from various leak databases.

    Ransomware Radar! 🔒: Keep a keen eye on ransomware attacks reported by sources like Ransomwarelive, Redpacket, and more.

## How to Use AGORA?

AGORA is as easy as pie to use! Simply run the program with a few command-line arguments, and voila! You'll have a wealth of cybersecurity information at your disposal. Here's a sneak peek:

### Example 1: Fetch Cybersecurity News
```bash
python Agora.py --argument news --keyword "Sandworm" --start-date "2023-01-01" --end-date "2024-01-01" --verbose
```
### Example 2: Explore CVEs

```bash
python Agora.py --argument cve --keyword "Fortinet" --start-date "2023-01-01" --end-date "2023-12-31" --verbose
```

This command will display CVEs related to exploits reported in 2023 with detailed descriptions.

### Example 3: Investigate Leaks

```bash
python Agora.py --argument leak --start-date "2023-01-01" --end-date "2023-12-31" --verbose
```

This command will provide information about data breaches and leaks reported in 2023 with verbose descriptions.  

### Example 4: Monitor Ransomware

```bash
python Agora.py --argument ransom --keyword "LockBit" --start-date "2023-01-01" --end-date "2023-12-31" --verbose
```

This command will show ransomware attacks involving the LockBit variant reported in 2023 with detailed information.  

### Example 5: Monitor Threat intel

```bash
python Agora.py --argument threat_intel --start-date "2024-01-01" --end-date "2024-06-31" --verbose
```

This command will show threat intel articles. 

### Example 6: Monitor OSINT

```bash
python Agora.py --argument osint --start-date "2024-01-01" --end-date "2024-06-31" --verbose
```

This command will show OSINT articles.

### Command-Line Arguments

    --argument: Choose between news, cve, leak, ransom, threat_intel or osint.
    --keyword: Filter articles by a specific keyword.
    --start-date: Filter starting from this date (YYYY-MM-DD).
    --end-date: Filter until this date (YYYY-MM-DD).
    --verbose: For more detailed information.


## Installation

To install the required dependencies, simply run:

```bash
git clone https://github.com/WOthm/Agora.git
cd Agora
pip install -r requirements.txt
```
Let AGORA Be Your Cyber Guide!

So, why wait? Let AGORA be your cyber guide in this vast digital wilderness. Sit back, relax, and let the cybersecurity updates come to you! 🎩✨

Happy Exploring with AGORA! 🚀🔍



