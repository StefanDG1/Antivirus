from customtkinter import *
from os import path, walk
from os.path import *
import hashlib
import requests
import json


# initializing the customtkinter app window and giving it dimensions and a title
app = CTk()
app.geometry("800x600")
app.title("Antivirus")

# creating an empty string and tuple where the dir and filenames will be stored
dirname = ''
filenames = ()
dir_selected = 0
file_list = []
hash_list = []
hash_index = []


# function to make a list with the absolute paths of all needed files
def get_file_list():
    global file_list
    file_list = []
    if dirname != '':
        # use the os.walk() function to get the file names in all subdirectories 
        for root, dirs, files in walk(os.path.abspath(dirname)):
            for file in files:
                file_list.append(path.join(root, file))
    else:
        file_list = [path.abspath(file) for file in filenames]

# inspiration from https://howtodoinjava.com/python-modules/python-find-file-hash/
def hash_files():
    
    global hash_list
    hash_list = []
    # iterate through every filename in the file list
    for filename in file_list:
        # make a new hash object for each file
        md5_h = hashlib.md5()
        # open file for reading in binary mode
        with open(filename,'rb') as file:
        # read file in chunks and update hash
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024) 
                md5_h.update(chunk)
        # get the hex digest and append it to the hash list
        hash_list.append(md5_h.hexdigest())
    print(hash_list)

def virus_scan():
    global hash_index
    hash_index = []
    with open("./full_md5.txt", "r") as hash_db:
        hashes = hash_db.read().splitlines()
        for i, hash in enumerate(hash_list):
            if(hash in hashes):
                hash_index.append(i)

    print(hash_index)
    for index in hash_index:
        print(file_list[index])


def run_scan():
    get_file_list()
    hash_files()
    virus_scan()
    #if(virusTotal_selected):
    for hash in hash_list:
        result = virusTotal_scan(hash)
        print(result)


# function to open the dialog box to select a directory and stores it in the dirname string
def dir_dialog():
    global dirname
    global filenames
    file_list = []
    filenames = ()
    dirname = filedialog.askdirectory()
    print(dirname)
    file_label.configure(text=f"Selected files: ")
    dir_label.configure(text=f"Selected directory: {dirname}")

# function to open the dialog box to select filenames and stores it in the dirname tuple
def filenames_dialog():
    global dirname
    global filenames
    file_list = []
    dirname = ''
    filenames = filedialog.askopenfilenames()
    print(filenames)
    dir_label.configure(text=f"Selected directory: ")
    if len(filenames) > 1:
        file_label.configure(text=f"Selected files: {str(filenames).strip('()')}")
    else:
        file_label.configure(text=f"Selected files: {str(filenames).strip('(,)')}")


def virusTotal_scan(id):
    url = f"https://www.virustotal.com/api/v3/files/{id}"
    api_key = "8da3c1b86b591198d304fbb6ee71f586057cef49ca8065cb3d9d2e2144e4e40a"

    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)
    res_json = response.json()
    try:
        res_attributes = res_json["data"]["attributes"]

        name = res_attributes["meaningful_name"]
        community_score_harmless, community_score_malicious = res_attributes["total_votes"]["harmless"], res_attributes["total_votes"]["malicious"]
        analysis_stats = res_attributes["last_analysis_stats"]
        total = 0
        for stat in analysis_stats:
            total += analysis_stats[stat]
        an_harmless = analysis_stats["harmless"]
        an_malicious = analysis_stats["malicious"] + analysis_stats["suspicious"]
        an_undetected = analysis_stats["undetected"]
        if (an_malicious > 0.7 * total):
            analysis_result = "critical"
        elif (an_malicious > 0.5 * total):
            analysis_result = "high"
        elif (an_malicious > 0.3 * total):
            analysis_result = "medium"
        else: analysis_result = "low"

        print(f"The name of the malware is {name}, {community_score_harmless} people from the community scored it as harmless while {community_score_malicious} scored it as malicious. From the last analysis, this many antiviruses flagged it as: {an_harmless} harmless, {an_malicious} malicious, {an_undetected} undetected.\n\tThe result of the scan is {analysis_result}")
        result = {
            "name": name,
            "community_score_harmless": community_score_harmless,
            "community_score_malicious": community_score_malicious,
            "analysis_harmless": an_harmless,
            "analysis_malicious": an_malicious,
            "analysis_undetected": an_undetected,
            "analysis_result": analysis_result
        }
        return result
    except:
        return "error"

# creating the buttons with their correct commands and placing them in the window, as well as their labels
dir_btn = CTkButton(app, text="Select Directory", command=dir_dialog)
dir_btn.place(relx=0.5, rely=0.5, anchor="center")
dir_label = CTkLabel(app, text="Selected directory:", fg_color="transparent")
dir_label.place(relx=0.5, rely=0.55, anchor="center")

file_btn = CTkButton(app, text="Select Files", command=filenames_dialog)
file_btn.place(relx=0.5, rely=0.6, anchor="center")
file_label = CTkLabel(app, text="Selected files:", fg_color="transparent")
file_label.place(relx=0.5, rely=0.65, anchor="center")

run_btn = CTkButton(app, text="Run Scan", command=run_scan)
run_btn.place(relx=0.5, rely=0.3, anchor="center")


app.mainloop()