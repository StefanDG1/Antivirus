from customtkinter import *
from os import path, walk
from os.path import *
import hashlib
import requests
import json


# initializing the customtkinter app window and giving it dimensions and a title
width = 800
height = 600
app = CTk()
app.geometry(f"{width}x{height}")
app.title("Antivirus")

# creating an empty string and tuple where the dir and filenames will be stored
dirname = ''
filenames = ()
dir_selected = 0
file_list = []
hash_list = []
bad_files_index = []


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
    global bad_files_index
    bad_files_index = []
    with open("./full_md5.txt", "r") as hash_db:
        hashes = hash_db.read().splitlines()
        for i, hash in enumerate(hash_list):
            if(hash in hashes):
                bad_files_index.append(i)

    print(bad_files_index)
    for index in bad_files_index:
        print(file_list[index])


def run_scan():
    get_file_list()
    hash_files()
    virus_scan()
    if(switch_vt.get() == "on"):
        for i, hash in enumerate(hash_list):
            result = virusTotal_scan(hash, i)
            print(result)
    print(bad_files_index)
    for index in bad_files_index:
        print(file_list[index])


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
            if (i not in bad_files_index):
                    bad_files_index.append(i)
        elif (an_malicious > 0.5 * total):
            analysis_result = "high"
            if (i not in bad_files_index):
                    bad_files_index.append(i)
        elif (an_malicious > 0.3 * total):
            analysis_result = "medium"
            if (i not in bad_files_index):
                    bad_files_index.append(i)
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


# top frame where buttons are placed
frame_top = CTkFrame(master=app, fg_color="red", width=200, height=50)
frame_top.pack(side="top", fill="x")
frame_top.pack_propagate(False)

dir_btn = CTkButton(frame_top, text="Select Directory", command=dir_dialog)
dir_btn.pack(side="left")
dir_label = CTkLabel(frame_top, text="Selected directory:", fg_color="transparent")
dir_label.pack(side="left")

file_btn = CTkButton(frame_top, text="Select Files", command=filenames_dialog)
file_btn.pack(side="left")
file_label = CTkLabel(frame_top, text="Selected files:", fg_color="transparent")
file_label.pack(side="left")
run_btn = CTkButton(frame_top, text="Run Scan", command=run_scan)
run_btn.pack(side="right")

switch_vt = StringVar(value="off")
switch = CTkSwitch(frame_top, text="VirusTotal Scan", variable=switch_vt, onvalue="on", offvalue="off")
switch.pack(side="left")

# add and remove files in the left frame
file_labels = []
frame_left = CTkFrame(master=app, fg_color="blue", width=300, height=50)
frame_left.pack(side="left", expand=True, fill="both")
for i in range(5):
    dir_label = CTkLabel(frame_left, text="Selected directory:", fg_color="transparent")
    dir_label.pack(side="top")
    file_labels.append(dir_label)

print(file_labels)
file_labels[3].destroy()
file_labels.pop(3)
print(file_labels)


frame_right = CTkFrame(master=app, fg_color="green", width=300, height=50)
frame_right.pack(side="right", expand=True, fill="both")


app.mainloop()