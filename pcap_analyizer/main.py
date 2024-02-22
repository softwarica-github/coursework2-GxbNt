from tkinter import *
from tkinter import filedialog, messagebox
from customtkinter import *
import pandas as pd
from pandastable import Table
import binascii
from scapy.all import *
# from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers import http
from PIL import Image, ImageTk
import os


PATH = os.path.dirname(os.path.realpath(__file__))

set_appearance_mode("dark")  # Modes: system (default), light, dark
set_default_color_theme("blue")  # Themes: blue (default), dark-blue, green

base = CTk()  # create CTk window like you do with the Tk window
base.geometry("900x790")
base.title("Pcap_Analyizer (Network Packet Analyzer) | Author: @Bishal Ray")
base.resizable(False, False)
if os.name == "posix":
    base.iconbitmap(r'@assets/baseIcon.xbm')
else:
    base.iconbitmap('assets/baseIcon.ico')

image_size = 30

file_entry_image = ImageTk.PhotoImage(
                    Image.open(PATH + "/assets/folder.webp").resize((image_size, image_size), 
                    Image.Resampling.LANCZOS))
file_analyze_image = ImageTk.PhotoImage(
                    Image.open(PATH + "/assets/analyze.webp").resize((image_size, image_size), 
                    Image.Resampling.LANCZOS))

frame1 = LabelFrame(base, 
                    highlightbackground="grey", 
                    width=550, 
                    height=50, 
                    highlightthickness=3, 
                    text="Selection Section", 
                    background="#302c2c", 
                    foreground="white",
                    labelanchor=N,
                    font=("Times", "16", "bold italic"))
frame1.grid(row=0, column=0, padx=100, pady=50, ipadx=20, ipady=20)

file_label = CTkLabel(frame1, text="Enter a path to pcap file:")
file_label.grid(row=0, column=0, padx=10, pady=10)

file_entry = CTkEntry(frame1, width=200)
file_entry.grid(row=0, column=1, padx=10, pady=10)

def filebrowse():
    filebrowser = filedialog.askopenfilename(title="Select a file", filetypes=(("pcap files", "*.pcap"), ("all files", "*.*")))
    file_entry.delete(0, END)
    file_entry.insert(0, str(filebrowser))
    return

file_search_button = CTkButton(frame1,
                                text="Browse", 
                                command=filebrowse, 
                                image=file_entry_image,
                                width=190, 
                                height=40,
                                hover_color="orange")

file_search_button.grid(row=0, column=2)

analyze_progres = CTkProgressBar(frame1, width=100)
analyze_progres.grid(row=1, column=2)
analyze_progres.set(0.35)
analyze_progres.configure(fg_color="white",
                      progress_color="green")

def analyzer():
    analyze_progres.set(0)
    base.update_idletasks()
    if file_entry.get() == "":
        messagebox.showerror("Error", "Please enter a path to a pcap file")

    else:
        try:
            file_name = file_entry.get()
            file_name_split = file_name.split("/")
            file_name_split = file_name_split[-1].split(".")
            file_extension = file_name_split[-1]

            if file_extension == "pcap" or file_extension == "pcapng":
                global df
                
                packets = rdpcap(file_entry.get())
                ip_fields = [field.name for field in IP().fields_desc]
                tcp_fields = [field.name for field in TCP().fields_desc]
                # udp_fields = [field.name for field in UDP().fields_desc]

                dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex'] 

                df = pd.DataFrame(columns=dataframe_fields) # create dataframe
                for packet in packets[IP]:
                    # Field array for each row of DataFrame
                    field_values = []
                    # Add all IP fields to dataframe
                    for field in ip_fields:
                        if field == 'options':
                            # Retrieving number of options defined in IP Header
                            field_values.append(len(packet[IP].fields[field]))
                        else:
                            field_values.append(packet[IP].fields[field])
                    
                    field_values.append(packet.time)
                    layer_type = type(packet[IP].payload)
                    for field in tcp_fields:
                        try:
                            if field == 'options':
                                field_values.append(len(packet[layer_type].fields[field]))
                            else:
                                field_values.append(packet[layer_type].fields[field])
                        except:
                            field_values.append(None)
                    
                    # Append payload
                    field_values.append(len(packet[layer_type].payload))
                    field_values.append(packet[layer_type].payload.original)
                    field_values.append(binascii.hexlify(packet[layer_type].payload.original))
                    # Add row to DF
                    df_append = pd.DataFrame([field_values], columns=dataframe_fields)
                    df = pd.concat([df, df_append], axis=0)

                # Reset Index
                df = df.reset_index()
                # Drop old index column
                df = df.drop(columns="index")
                
                analyze_progres.set(1)
                
                create_table_button.configure(state=NORMAL)
                password_button.configure(state=NORMAL)
                summarizer_button.configure(state=NORMAL)
                choosed_cols_button.configure(state=NORMAL)
                view_cols.configure(state=NORMAL)
                
 
            else:
                messagebox.showerror("Error", "File must be a pcap or pcapng file")
                
        except:
            pass


file_analyze = CTkButton(frame1, 
                        text="Analyze", 
                        command=analyzer, 
                        image=file_analyze_image, 
                        width=190, 
                        height=40,
                        hover_color="orange")
file_analyze.grid(row=1, column=1)



frame2 = LabelFrame(base, 
                    highlightbackground="grey", 
                    width=730, 
                    height=50, 
                    highlightthickness=3, 
                    text="Analyze Section", 
                    background="#302c2c", 
                    foreground="white",
                    labelanchor=N,
                    font=("Times", "16", "bold italic"))
frame2.grid(row=1, column=0, padx=20, pady=15, ipadx=20, ipady=20)

def viewTable():
    table_show = Toplevel()
    table_show.title("Table Frame")
    table_show.geometry("1000x600")
    table = Table(table_show, dataframe=df, showtoolbar=True, showstatusbar=True, width=1500, height=800)
    table.show()

create_table_button = CTkButton(frame2, 
                                text="Pcap Table View", 
                                command=viewTable, 
                                state=DISABLED,
                                width=190, 
                                height=40,
                                hover_color="orange")
create_table_button.grid(row=0, column=1, padx=30, pady=20)

def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        return url

def get_login_info(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(Raw):
            load = packet[Raw].load
            #load = str(load)
            keybword = ["usr", "uname", "username", "pwd", "pass", "password"]
            for eachword in keybword:
                if eachword.encode() in load:
                    return load

def passwordView():
    packets = rdpcap(file_entry.get())

    logins = {"URL": [], "Login Info": []}
    for i in range(len(packets)):
        if packets[i].haslayer(http.HTTPRequest):
            url = get_url(packets[i]).decode('utf-8')
            login_info = get_login_info(packets[i])
            if login_info:
                logins['URL'].append(str(url))
                logins['Login Info'].append(login_info)

    if len(logins['URL']) == 0:
        messagebox.showerror("Error", "No login information found")
    else:
        login_dataframe = pd.DataFrame(logins)
        table_show = CTkToplevel()
        table_show.title("Table Frame")
        table_show.geometry("1000x600")
        table = Table(table_show, dataframe=login_dataframe, showtoolbar=True, showstatusbar=True, width=1500, height=800)
        table.show()
    
    


password_button = CTkButton(frame2, 
                            text="HTTP Passwords", 
                            command=passwordView, 
                            state=DISABLED,
                            width=190, 
                            height=40,
                            hover_color="orange")
password_button.grid(row=0, column=2, padx=80, pady=20)

def summarize():
    summary = CTkToplevel()
    summary.title("Summary")
    summary.geometry("1000x600")

    frequent_address = df['src'].describe()['top']

    filename = file_entry.get()
    packets = rdpcap(filename)
    filename = filename.split("/")
    filename = filename[-1]
    
    text = f"""
This file ({filename}) has {len(packets)} packets.

Unique Source Addresses
{df['src'].unique()}

Unique Destination Addresses
{df['dst'].unique()}

Top Source Address
{df['src'].describe()}

Top Destination Address
{df['dst'].describe()}

# Who is Top Address Speaking to?"
{df[df['src'] == frequent_address]['dst'].unique()}

# Who is the top address speaking to (Destination Ports)
{df[df['src'] == frequent_address]['dport'].unique()}

# Who is the top address speaking to (Source Ports)
{df[df['src'] == frequent_address]['sport'].unique()}
"""
    summary.grid_rowconfigure(0, weight=1)
    summary.grid_columnconfigure(0, weight=1)

    # create scrollable textbox
    tk_textbox = Text(summary, highlightthickness=0)
    tk_textbox.grid(row=0, column=0, sticky="nsew")

    tk_textbox.insert(END, text)
    # create CTk scrollbar
    ctk_textbox_scrollbar = CTkScrollbar(summary, command=tk_textbox.yview)
    ctk_textbox_scrollbar.grid(row=0, column=1, sticky="ns")

    # connect textbox scroll event to CTk scrollbar
    tk_textbox.configure(yscrollcommand=ctk_textbox_scrollbar.set)



summarizer_button = CTkButton(frame2, 
                                text="Summarizer", 
                                command=summarize, 
                                state=DISABLED,
                                width=190, 
                                height=40,
                                hover_color="orange")
summarizer_button.grid(row=0, column=4, padx=10, pady=20)

def show_columns():
    show_cols = CTkToplevel()
    show_cols.title("Columns Names")
    cols = []
    for i in range(len(df.columns)):
        cols.append(df.columns[i])
    cols = str(cols)
    cols_label = Label(show_cols, text=cols)
    cols_label.pack()
    
view_cols = CTkButton(frame2, 
                    text="View Columns", 
                    command=show_columns, 
                    state=DISABLED,
                    width=190, 
                    height=40,
                    hover_color="orange")

view_cols.grid(row=3, column=2,pady=20)

def preferred_table():
    try:
        cols = choosed_cols.get()
        cols = cols.split()
        if choosed_cols.get() == "":
            messagebox.showerror("Error", "Try entering the columns name separated by space")
        else:
            ip_show = CTkToplevel()
            ip_show.title("Preferred Table")
            ip_show.geometry("1000x600")
            
            table = Table(ip_show, dataframe=df[cols], showtoolbar=True, showstatusbar=True, width=1500, height=800)
            table.show()
    except:
        messagebox.showerror("Error", "Only No Column with that name Exists! Try seeing the column names")


choosed_cols = CTkEntry(frame2, width=200)
choosed_cols.grid(row=1, column=2, padx=10, pady=10)

choosed_cols_button = CTkButton(frame2, 
                                text="Choose columns", 
                                command=preferred_table, 
                                state=DISABLED,
                                width=190, 
                                height=40,
                                hover_color="orange")
choosed_cols_button.grid(row=2, column=2)

base.mainloop()
