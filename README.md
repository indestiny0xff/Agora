AGORA - Your Cybersecurity Info Companion! 🛡️🌐

Welcome to AGORA, your one-stop destination for all things cybersecurity! 🚀

Are you tired of endlessly scrolling through various websites, blogs, and feeds to stay updated on the latest cyber threats, vulnerabilities, leaks, and ransomware attacks? Fear not! AGORA is here to save your day, providing you with curated and filtered information from a plethora of sources, all in one place!
What Does AGORA Offer?

News Galore! 📰: Dive into the latest cybersecurity news from renowned sources like TheHackerNews, Threatpost, KrebsOnSecurity, and many more!

CVEs at Your Fingertips! 💣: Stay informed about Common Vulnerabilities and Exposures (CVEs) from authoritative sources such as CISA.

Leak Investigations! 🕵️: Explore data breaches and leaks with ease, thanks to AGORA's comprehensive coverage from various leak databases.

Ransomware Radar! 🔒: Keep a keen eye on ransomware attacks reported by sources like Ransomwarelive, Redpacket, and more.

How to Use AGORA?

AGORA is as easy as pie to use! Simply run the program with a few command-line arguments, and voila! You'll have a wealth of cybersecurity information at your disposal. Here's a sneak peek:
Example 1: Fetch Cybersecurity News

python agora.py --argument news --keyword "cybersecurity" --start-date "2023-01-01" --end-date "2024-01-01" --verbose

Example 2: Explore CVEs

python agora.py --argument cve --keyword "Ivanti" --start-date "2023-01-01" --end-date "2023-12-31" --verbose

This command will display CVEs related to exploits reported in 2023 with detailed descriptions.
Example 3: Investigate Leaks

python agora.py --argument leak --start-date "2023-01-01" --end-date "2023-12-31" --verbose

This command will provide information about data breaches and leaks reported in 2023 with verbose descriptions.
Example 4: Monitor Ransomware

python agora.py --argument ransom --keyword "LockBit" --start-date "2023-01-01" --end-date "2023-12-31" --verbose

This command will show ransomware attacks involving the LockBit variant reported in 2023 with detailed information.
Command-Line Arguments

--argument: Choose between news, CVE, leak, or ransom.
--keyword: Filter articles by a specific keyword.
--start-date: Filter starting from this date (YYYY-MM-DD).
--end-date: Filter until this date (YYYY-MM-DD).
--verbose: For more detailed information.

### Installation

To install the required dependencies, simply run:

pip install -r requirements.txt

Let AGORA Be Your Cyber Guide!

So, why wait? Let AGORA be your cyber guide in this vast digital wilderness. Sit back, relax, and let the cybersecurity updates come to you! 🎩✨

Happy Exploring with AGORA! 🚀🔍
