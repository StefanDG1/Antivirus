### Github link
https://github.com/StefanDG1/Antivirus/


### Antivirus Project that gets the hash signature of files and compares them to a malware hash database and uses the VirusTotal api to run a scan on the selected files.

The database of MD5 hashes was obtained from https://bazaar.abuse.ch/export/txt/md5/full/

To get the eicar test file (harmless file that is used for testing):
(windows antivirus will usually detect the file automatically and delete it, so I have done my testing on a linux machine)
wget https://www.eicar.org/download/eicar-com/?wpdmdl=8840&refresh=655626dfa147a1700144863

If there are no malicious files then after running the scan it will seem like nothing happened, since none where detected. With no malicious files, it is hard/impossible to test the selection and delete functions of the app.

### Report
Name: Stefan Daniel Gheorghiu
Title: Antivirus
Project description: Python antivirus that selects files and scans them against a database of known malicious hashes and/or runs a scan using the VirusTotal api to determine how secure the files are.

### Architecture
The GUI part is at the bottom, placing all the elements and buttons.
You can select specific files or all files in a directory.
There is a switch to determine wether to run the VirusTotal scan or not.
The main function that hashes and runs the scans, then displays the files is the run_scan() function.
In both cases, the selected files are hashed and then compared to the md5 database of malicious hashes. If a hash is the same as a hash in the file, that file is marked as malicious.
If virustotal is enabled, the hash is also scanned with the api and the desired information is extracted from the result.
Then, the files are displayed (if there are any malicious ones).
These files can be clicked to select them and display more info about them, and clicked again to unselect them. Multiple files can be clicked and selected. There are 2 delete buttons, the delete selected and delete all. After clicking any delete buttons, the reset function is ran always, so if you deleted a selection but not all and want to go back to delete more of those files, you cannot and must run the scan again.
