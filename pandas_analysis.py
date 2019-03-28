import pandas as p
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import time

phone_ip = "192.168.137.186"
sns.set_style("darkgrid")
# sns.set_palette("bright")

title_font = {'fontname': 'Arial', 'size': '20', 'color': 'black', 'weight': 'normal',
              'verticalalignment': 'bottom'}  # Bottom vertical alignment for more space
axis_font = {'fontname': 'Arial', 'size': '16', 'color': 'black', 'weight': 'normal'}  # Bottom vertical alignment for more space
label_font = {'fontname': 'Arial', 'size': '12', 'color': 'black', 'weight': 'normal'}

def frames_over_time(path, sheet):
    df = p.read_excel(path, index_col=None, sheet_name = sheet)
    df['Timestamp'] = p.to_datetime(df['Timestamp'], unit='s')
    df['Time'] = df["Timestamp"].dt.strftime("%H:%M")

    to_phone, from_phone = [x for _, x in df.groupby(df['Src IP'] == phone_ip)]
    
    def create_graph(dataset):
        dataset = dataset.groupby(['Service', 'Time'])['Frame Size'].sum()
        dataset = dataset.to_frame()
        ads = dataset['Frame Size']['ads'].reset_index().rename(
            columns={"Frame Size": "Advertisements"})
        benign = dataset['Frame Size']['benign'].reset_index().rename(
            columns={"Frame Size": "Benign"})
        # print(benign)
        tracking = dataset['Frame Size']['tracking'].reset_index().rename(
            columns={"Frame Size": "Tracking"})
        both = dataset['Frame Size']['ads,tracking'].reset_index().rename(
            columns={"Frame Size": "Both"})


        fig, ax = plt.subplots()
        ax.plot(benign["Time"], benign["Benign"], '-o')
        ax.plot(both["Time"], both["Both"], '-o')
        ax.plot(ads["Time"], ads["Advertisements"], '-o')
        ax.plot(tracking["Time"], tracking["Tracking"], '-o')
        ax.set_xticklabels(benign["Time"])
        plt.xticks(np.arange(len(benign["Time"])))
        plt.xlabel("Time")
        plt.ylabel("Total Frame Size")
        plt.legend()
        plt.show()
    
    create_graph(to_phone)
    create_graph(from_phone)

def graph_ad_ips(path):
    df = p.read_excel("./results/Android9.0/Pandas Datasets/summary.xlsx", index_col=None)

    ad_ips = df.groupby('Ad IPs')['Filename'].count()
    tracking_ips = df.groupby('Tracking Ips')['Filename'].count()

    data_ips = {'Advertisments': ad_ips, 'Tracking IPs': tracking_ips}
    all_ips = p.DataFrame(data=data_ips)

    ax = all_ips.plot(kind='bar', stacked=True, figsize=(11, 7), rot=0)
 
    ax.yaxis.set_major_locator(plt.FixedLocator(range(0,len(all_ips)+1)))
    plt.xticks(**label_font)
    plt.yticks(**label_font)
    plt.title("Distribution of Unique Connections", **title_font)
    plt.xlabel("Number of Unique IP Connections", **axis_font)
    plt.ylabel("Number of Applications", **axis_font)
    plt.legend(loc=1, fontsize=12)
    plt.savefig("./graphs/num_ad_ips.png")
    plt.show()

graph_ad_ips("./results/Android9.0/android_combined_results.xlsx")
# frames_over_time("./results/Android9.0/android_combined_results.xlsx", "com.amanotes.beathopper.apk.pca")

df = p.read_excel(
    "./results/Android9.0/Pandas Datasets/summary.xlsx", index_col=None)

print("Max ad traffic...")
print(df[df["Ad Traffic Size"] == df["Ad Traffic Size"].max()])
print("Max ad ips...")
print(df[df["Ad IPs"] == df["Ad IPs"].max()])
