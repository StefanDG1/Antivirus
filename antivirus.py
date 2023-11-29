from customtkinter import *
from os import path, walk, remove
from hashlib import md5
from requests import get


# initializing the customtkinter app window and giving it dimensions and a title
width = 800
height = 600
app = CTk()
app.geometry(f"{width}x{height}")
app.title("Antivirus")

# initializing the empty variables that will be needed later
dirname = ''
filenames = ()
file_list = []
hash_list = []
bad_files_index = []
file_selection = []
results_list = []
info_dict = {}
file_labels = []
bad_file_labels = []


# reset function
def reset_all():
    global dirname
    global filenames
    global file_list
    global hash_list
    global bad_files_index
    global file_selection
    global results_list
    global info_dict
    global file_labels
    global bad_file_labels
    if (len(file_labels) > 0):
        for label in file_labels:
            label.destroy()
    if (len(bad_file_labels) > 0):
        for label in bad_file_labels:
            label.destroy()
    info_label.configure(text='')

    
    dirname = ''
    filenames = ()
    file_list = []
    hash_list = []
    bad_files_index = []
    file_selection = []
    results_list = []
    info_dict = {}
    file_labels = []
    bad_file_labels = []


# function to make a list with the absolute paths of all needed files
def get_file_list():
    global file_list
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
        md5_h = md5()
        # open file for reading in binary mode
        with open(filename,'rb') as file:
        # read file in chunks and update hash
            chunk = 0
            while chunk != b'':
                chunk = file.read(1024) 
                md5_h.update(chunk)
        # get the hex digest and append it to the hash list
        hash_list.append(md5_h.hexdigest())

# open the md5 hash file and compare hashes to hashes from file, if found add to the bad files list
def virus_scan():
    global bad_files_index
    bad_files_index = []
    with open("./full_md5.txt", "r") as hash_db:
        hashes = hash_db.read().splitlines()
        for i, hash in enumerate(hash_list):
            if(hash in hashes):
                bad_files_index.append(i)

# run scan function that runs other functions as needed
def run_scan():
    # reset bad files and selection if you want to run the scan again with virustotal on/off
    if (len(bad_file_labels) > 0):
        for label in bad_file_labels:
            label.destroy()
    info_label.configure(text='')
    global file_selection
    file_selection = []
    
    hash_files()
    virus_scan()
    global info_dict
    global results_list
    if(switch_vt.get() == "on"):
        for i, hash in enumerate(hash_list):
            result = virusTotal_scan(hash, i)
            results_list.append(result)
        info_dict = {bad_files_index[i]: results_list[i] for i in range(len(bad_files_index))}
    display_bad_files(bad_files_index)

# create labels to display the path of the files on the screen
def display_files():
    global file_labels
    get_file_list()
    file_labels = [None] * len(file_list)

    for i in range(len(file_labels)):
        file_labels[i] = CTkLabel(scrollable_frame_top, text=file_list[i], fg_color="#3B8ED0", corner_radius=8, padx=10)
        file_labels[i].pack(side="top")

# create clickable buttons (with the selected() lambda function to be able to pass an argument 
# and only call it when it is clicked) to display the malicious files
def display_bad_files(bad_indexes):
    global bad_file_labels
    bad_file_labels = [None] * len(bad_indexes)

    for i in range(len(bad_file_labels)):
        bad_file_labels[i] = CTkButton(scrollable_frame_bottom, text=file_list[bad_indexes[i]], command= lambda id=i: selected(id), hover_color="#c70000", fg_color="#3B8ED0")
        bad_file_labels[i].pack(side="top")

# function to open the dialog box to select a directory and stores it in the dirname string
def dir_dialog():
    reset_all()
    global dirname
    dirname = filedialog.askdirectory()
    display_files()


# function to open the dialog box to select filenames and stores it in the dirname tuple
def filenames_dialog():
    reset_all()
    global filenames
    filenames = filedialog.askopenfilenames()
    display_files()

# use the VirusTotal api to extract data from a hash and return the result in a dictionary
def virusTotal_scan(id, i):
    url = f"https://www.virustotal.com/api/v3/files/{id}"
    api_key = "8da3c1b86b591198d304fbb6ee71f586057cef49ca8065cb3d9d2e2144e4e40a"

    headers = {"x-apikey": api_key}

    response = get(url, headers=headers)
    res_json = response.json()
    # error can be from limit being reached or file not existing in their database
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

# remove all malicious files
def remove_files():
    for index in bad_files_index:
        os.remove(file_list[index])
    reset_all()

# remove selected files
def remove_selection():
    for file in file_selection:
        os.remove(file)
    reset_all()



# use the dictionary with results to change the info text
def change_info_text(index):
    # if no info cause virustotal wasn't selected
    try:
        info_data = info_dict[index]
        info_text = f"Details of file:\nThe name of the file is {info_data['name']}.\nThe community score is: {info_data['community_score_harmless']} as harmless and {info_data['community_score_malicious']} as malicious.\nThis many antiviruses scored it as: harmless {info_data['analysis_harmless']} | malicious {info_data['analysis_malicious']} | undetected {info_data['analysis_undetected']} \nThe estimated danger level is: {info_data['analysis_result']}"
        info_label.configure(text=info_text)
    except: pass

# change colors and add/remove files from selection toggle
def selected(num):
    global file_selection
    label_obj = bad_file_labels[num]
    text = label_obj.cget("text")
    if label_obj.cget("fg_color") == "#3B8ED0":
        file_selection.append(text)
        change_info_text(num)
        label_obj.configure(fg_color="#c70000")
        label_obj.configure(hover_color="#990000")
    else:
        file_selection.remove(text) 
        label_obj.configure(fg_color="#3B8ED0")
        label_obj.configure(hover_color="#c70000")


# left frame where buttons are placed
container_left = CTkFrame(master=app, fg_color="#F6F4EB", width=150, corner_radius=0)
container_left.pack(side="left", fill="y")
container_left.pack_propagate(False)

dir_btn = CTkButton(container_left, text="Select Directory", command=dir_dialog)
dir_btn.place(rely=0.25, relx=0.5, anchor="center")

file_btn = CTkButton(container_left, text="Select Files", command=filenames_dialog)
file_btn.place(rely=0.31, relx=0.5, anchor="center")

switch_vt = StringVar(value="off")
switch = CTkSwitch(container_left, text="VirusTotal Scan", variable=switch_vt, onvalue="on", offvalue="off")
switch.place(rely=0.36, relx=0.5, anchor="center")

run_btn = CTkButton(container_left, text="Run Scan", command=run_scan)
run_btn.place(rely=0.45, relx=0.5, anchor="center")

delete_btn = CTkButton(container_left, text="Delete Selected Files", command=remove_selection, fg_color="#c70000", hover_color="#990000")
delete_btn.place(rely=0.85, relx=0.5, anchor="center")
delete_all_btn = CTkButton(container_left, text="Delete all files", command=remove_files, fg_color="#c70000", hover_color="#990000")
delete_all_btn.place(rely=0.91, relx=0.5, anchor="center")



# right frame split into 2 parts, top and bottom
container_right = CTkFrame(master=app, corner_radius=0)
container_right.pack(side="right", expand=True, fill="both")

# top part
frame_top = CTkFrame(master=container_right, corner_radius=0)
frame_top.pack(side="top", expand=True, fill="both")
frame_top.pack_propagate(False)

# scrollable frame in top frame
scrollable_frame_top = CTkScrollableFrame(master=frame_top, fg_color="#749BC2", border_color="#F6F4EB", border_width=1, corner_radius=0)
scrollable_frame_top.pack(expand=True, fill="both")
top_label = CTkLabel(master=scrollable_frame_top, text="Selected files")
top_label.pack(side="top")

# bottom part
frame_bottom = CTkFrame(master=container_right)
frame_bottom.pack(side="bottom", expand=True, fill="both")
frame_bottom.pack_propagate(False)

# scrollable bottom frame
scrollable_frame_bottom = CTkScrollableFrame(master=frame_bottom, fg_color="#4682A9", border_color="#F6F4EB", border_width=1, corner_radius=0)
scrollable_frame_bottom.pack(side="top", fill="both", expand=True)
bottom_label = CTkLabel(master=scrollable_frame_bottom, text="Malicious files")
bottom_label.pack(side="top")

# info section
frame_info = CTkFrame(master=frame_bottom, fg_color="#3B8ED0", border_color="#F6F4EB", border_width=1, corner_radius=0)
frame_info.pack(side="bottom", fill="both", expand=True)
info_sub_frame = CTkFrame(master=frame_info, fg_color="#3B8ED0")
info_sub_frame.pack(side="left", fill="both", expand=True)
info_label = CTkLabel(master=info_sub_frame, padx=30, pady=20, fg_color="transparent", text="The details of the malicious files is:")
info_label.pack(side="top")


app.mainloop()