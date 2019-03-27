import pandas as p
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import time

phone_ip = "192.168.137.186"
sns.set_style("darkgrid")
# sns.set_palette("bright")

def frames_over_time(path):
    df = p.read_excel(path, index_col=None)
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

path = "./results/Android9.0/Pandas Datasets/summary.xlsx"

df = p.read_excel(path, index_col=None, usecols="A,B,L,P")
print("Max ad traffic...")
print(df[df["Ad Traffic Size"] == df["Ad Traffic Size"].max()])
print("Max ad ips...")
print(df[df["Ad IPs"] == df["Ad IPs"].max()])

ad_ips = df.groupby(['Ad IPs'])['Ad Traffic Size'].sum()
ad_ips = ad_ips.iloc[1:, ]

fig, ax = plt.subplots()
ax.bar(np.arange(len(ad_ips.index)), ad_ips.values)
ax.set_xticklabels(ad_ips.index)
plt.xticks(np.arange(len(ad_ips.index)))
# print(np.arange(ad_ips.index))
plt.show()

frames_over_time("./results/Android9.0/Pandas Datasets/largest_ad_traffic(io.voodo.crowdcity).xlsx")
