from selenium import webdriver
import time
import subprocess
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlparse

website_list = ["https://www.google.com", "https://www.facebook.com", "https://www.youtube.com", "https://www.amazon.com", "https://www.reddit.com", "https://www.wikipedia.org", "https://www.yahoo.com", "https://www.twitter.com", "https://www.instagram.com", "https://www.linkedin.com"]

# Driver Options
s = Service(ChromeDriverManager().install())
options = Options()
options.add_argument("--headless")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")


for site in website_list:
    print("Scanning website: " + site)
    for i in range(50):
        try:
            domain_name = urlparse(site).netloc.split('.')[1]
            pcap_file = f"captured_data/{domain_name}_{i + 1}.pcap"

            tshark_cmd = ["tshark", "-i", "Wi-Fi", "-f", "udp port 443", "-w", pcap_file, "-l"]
            tshark_process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            driver = webdriver.Chrome(service=s, options=options)

            driver.get(site)
            time.sleep(5)

            driver.quit()
        finally:
            tshark_process.terminate()
            print("Stopped tshark scanning...")
            tshark_process.wait()