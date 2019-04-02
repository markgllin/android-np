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


def ips_over_time(path, sheet, app_name):
    df = p.read_excel(path, index_col=None, sheet_name=sheet)
    df['Timestamp'] = p.to_datetime(df['Timestamp'], unit='s')
    df['Time'] = df["Timestamp"].dt.strftime("%H:%M")

    to_phone, from_phone = [x for _, x in df.groupby(df['Src IP'] == phone_ip)]
    dataset_to = to_phone.groupby(['Service', 'Time'])['Src IP'].nunique()
    dataset_from = from_phone.groupby(['Service', 'Time'])['Dst IP'].nunique()

    def create_graph(dataset, column):
        dataset = dataset.to_frame()

        ads = dataset[column]['ads'].reset_index().rename(
            columns={column: "Advertisements"})
        benign = dataset[column]['benign'].reset_index().rename(
            columns={column: "Benign"})
        tracking = dataset[column]['tracking'].reset_index().rename(
            columns={column: "Tracking"})
        both = dataset[column]['ads,tracking'].reset_index().rename(
            columns={column: "Both"})

        fig, ax = plt.subplots(figsize=(11, 7))
        ax.plot(benign["Time"], benign["Benign"], '-o')
        ax.plot(both["Time"], both["Both"], '-o')
        ax.plot(ads["Time"], ads["Advertisements"], '-o')
        ax.plot(tracking["Time"], tracking["Tracking"], '-o')
        ax.set_xticklabels(range(0, 16))
        plt.xticks(np.arange(len(benign["Time"])), **label_font)
        plt.yticks(**label_font)
        plt.title("Total Number of Unique IP Connections over Time per IP Type", **title_font)
        plt.xlabel("Time (in minutes)", **axis_font)
        plt.ylabel("Total Number of Unique IP Connections", **axis_font)
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(dataset_to, "Src IP")
    plt.savefig("./graphs/ips_to_phone_(" + app_name + ").png")
    # plt.show()

    create_graph(dataset_from, "Dst IP")
    plt.savefig("./graphs/ips_from_phone_(" + app_name + ").png")
    # plt.show()

def frames_over_time(path, sheet, app_name):
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

        fig, ax = plt.subplots(figsize=(11,7))
        ax.plot(benign["Time"], benign["Benign"], '-o')
        ax.plot(both["Time"], both["Both"], '-o')
        ax.plot(ads["Time"], ads["Advertisements"], '-o')
        ax.plot(tracking["Time"], tracking["Tracking"], '-o')
        ax.set_xticklabels(range(0,16))
        # ax.set_zticklabels(benign["Time"])
        plt.xticks(np.arange(len(benign["Time"])), **label_font)
        plt.yticks(**label_font)
        plt.title("Total Traffic Sent over Time per IP Type", **title_font)
        plt.xlabel("Time (in minutes)", **axis_font)
        plt.ylabel("Total Traffic Sent (in bytes)", **axis_font)
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(to_phone)
    plt.savefig("./graphs/to_phone_(" + app_name + ").png")
    # plt.show()

    create_graph(from_phone)
    plt.savefig("./graphs/from_phone_(" + app_name + ").png")
    # plt.show()


def graph_ad_ips():
    df = p.read_excel("./results/Android9.0/Pandas Datasets/summary.xlsx", index_col=None)

    ad_ips = df.groupby('Ad IPs')['Filename'].count()
    tracking_ips = df.groupby('Tracking Ips')['Filename'].count()

    data_ips = {'Advertisments': ad_ips, 'Tracking IPs': tracking_ips}
    all_ips = p.DataFrame(data=data_ips)

    ax = all_ips.plot(kind='bar', stacked=False, figsize=(11, 7), rot=0, width=0.8)
 
    ax.yaxis.set_major_locator(plt.FixedLocator(range(0,len(all_ips)+1)))
    plt.xticks(**label_font)
    plt.yticks(**label_font)
    plt.title("Distribution of Unique Connections", **title_font)
    plt.xlabel("Number of Unique IP Connections", **axis_font)
    plt.ylabel("Number of Applications", **axis_font)
    plt.legend(loc=1, fontsize=12)
    plt.savefig("./graphs/num_ad_ips.png")
    # plt.show()

def total_number_vs_size():
    df = p.read_excel("./results/Android9.0/Pandas Datasets/summary.xlsx", index_col=None)

    frame_nums = df[['Filename', 'Begnign Frames', 'Ad Frames', 'Tracking Frames', 'Ad/Tracking Frames']]
    frame_size = df[['Filename', 'Benign Traffic Size', 'Ad Traffic Size', 'Tracking Traffic Size', 'Ad/Tracking Traffic Size']]

    frame_nums = frame_nums.groupby(['Begnign Frames']).sum()
    print(frame_nums.head(3))

def calculate_percentages():
    df = p.read_excel("./results/Android9.0/Pandas Datasets/summary.xlsx", index_col=None)

    print("Ad Percentage")
    row = df[df['Filename'] == "io.voodoo.paper2.apk.pcap"]
    total = row['Benign Traffic Size'] + \
    row['Ad Traffic Size'] + row['Tracking Traffic Size']
    print((row['Ad Traffic Size'] / total) * 100)
    print((row['Tracking Traffic Size'] / total) * 100)


def get_percentages(path):
    df = p.read_excel(path, index_col=None)
    df['Timestamp'] = p.to_datetime(df['Timestamp'], unit='s')
    df['Time'] = df["Timestamp"].dt.strftime("%H:%M")
    first = df['Time'][1]
    first = (p.to_datetime(first) + p.Timedelta(minutes=1)).strftime("%H:%M")
    df = df[df['Time'] > first]
    df = df.groupby(['Service'])['Frame Size'].sum()
    df = df.to_frame()

    total = sum(df['Frame Size'])
    ad_percent       = (df['Frame Size']['ads'] / total) * 100
    tracking_percent = (df['Frame Size']['tracking'] / total) * 100
    both_percent     = (df['Frame Size']['ads,tracking'] / total) * 100
    benign_percent   = (df['Frame Size']['benign'] / total) * 100

    print("Ads: %.2f \nTracking: %.2f\nBoth: %.2f\nBenign: %.2f"
        %(ad_percent, tracking_percent, both_percent, benign_percent))

get_percentages("./results/Android9.0/Pandas Datasets/io.voodoo.paper2.xlsx")

# graph_ad_ips()

ips_over_time(
    "./results/Android9.0/Pandas Datasets/io.voodoo.paper2.xlsx", "Sheet1", "io.voodoo.paper2")
frames_over_time(
    "./results/Android9.0/Pandas Datasets/io.voodoo.paper2.xlsx", "Sheet1", "io.voodoo.paper2")
ips_over_time(
    "./results/Android9.0/Pandas Datasets/io.voodoo.crowdcity.xlsx", "Sheet1", "io.voodoo.crowdcity")
frames_over_time(
    "./results/Android9.0/Pandas Datasets/io.voodoo.crowdcity.xlsx", "Sheet1", "io.voodoo.crowdcity")

df = p.read_excel("./results/Android9.0/Pandas Datasets/summary.xlsx", index_col=None)

print("Max ad traffic...")
print(df[df["Ad Traffic Size"] == df["Ad Traffic Size"].max()])

# print("Max ad ips...")
# print(df[df["Ad IPs"] == df["Ad IPs"].max()])
# print("Max tracking ips...")
# print(df[df["Tracking Ips"] == df["Tracking Ips"].max()])
# print("Max tracking traffic...")
# print(df[df["Tracking Traffic Size"] == df["Tracking Traffic Size"].max()])

# total_number_vs_size()

#  dataset_from = from_phone.groupby(['Service', 'Time'])['Dst IP'].nunique()
