### Antivirus Project that gets the hash signature of files and compares them to a malware hash database and uses the VirusTotal api to run a scan on the selected files.

The database of MD5 hashes was obtained from https://bazaar.abuse.ch/export/txt/md5/full/

To get the eicar test file (harmless file that is used for testing):
(windows antivirus will usually detect the file automatically and delete it, so I have done my testing on a linux machine)
wget https://www.eicar.org/download/eicar-com/?wpdmdl=8840&refresh=655626dfa147a1700144863

If there are no malicious files then after running the scan it will seem like nothing happened, since none where detected.