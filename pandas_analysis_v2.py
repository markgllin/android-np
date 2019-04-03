import pandas as p
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import time
import datetime

phone_ip = "192.168.137.186"
sns.set_style("darkgrid")
# sns.set_palette("bright")

title_font = {'fontname': 'Arial', 'size': '20', 'color': 'black', 'weight': 'normal',
              'verticalalignment': 'bottom'}  # Bottom vertical alignment for more space
axis_font = {'fontname': 'Arial', 'size': '16', 'color': 'black', 'weight': 'normal'}  # Bottom vertical alignment for more space
label_font = {'fontname': 'Arial', 'size': '12', 'color': 'black', 'weight': 'normal'}

############################################
#                HTTPS STUFF               #
############################################

def distribute_time(all_dfs):
    all_times = []
    for df in all_dfs:
        all_times += list(df["Time"])
    
    all_times = sorted(list(dict.fromkeys(all_times)))
    start = p.to_datetime(min(all_times))
    end = p.to_datetime(max(all_times))
    times = []
    while(start <= end):
        times.append(start.strftime("%H:%M"))
        start = start + p.Timedelta(minutes=1)

    time_range = p.DataFrame({'Time': times})
    cleaned = []
    for frame in all_dfs:
        clean = p.concat([time_range, frame], join="outer", sort=False)
        clean.drop_duplicates(subset=['Time'], keep='last', inplace=True)
        clean.sort_values(by=['Time'], inplace = True)
        clean = clean.reset_index().drop('index', axis=1)
        cleaned.append(clean)
    return cleaned

def get_all_dfs(dataset, column):
    service_types = list(dataset[column].index.levels[0])
    all_dfs   = []
    if 'benign' in service_types:
        benign = dataset[column]['benign'].reset_index().rename(columns={
            column: "Benign"})
        all_dfs.append(benign)
    if 'ads' in service_types:
        ads = dataset[column]['ads'].reset_index().rename(
            columns={column: "Advertisements"})
        all_dfs.append(ads)
    if 'tracking' in service_types:
        tracking = dataset[column]['tracking'].reset_index().rename(columns={
            column: "Tracking"})
        all_dfs.append(tracking)
    if 'ads,tracking' in service_types:
        both = dataset[column]['ads,tracking'].reset_index().rename(columns={
            column: "Both"})
        all_dfs.append(both)
    return all_dfs

def ips_over_time(path, sheet, app_name):
    df = p.read_excel(path, index_col=None, sheet_name=sheet)
    df['timestamp'] = p.to_datetime(df['timestamp'], unit='s')
    df['Time'] = df["timestamp"].dt.strftime("%H:%M")

    to_phone, from_phone = [x for _, x in df.groupby(df['src ip'] == phone_ip)]
    dataset_from = from_phone.groupby(['service', 'Time'])['dst ip'].nunique()

    def create_graph(dataset, column):
        dataset = dataset.to_frame()

        fig, ax = plt.subplots(figsize=(11, 7))
        service_types = list(dataset[column].index.levels[0])
        all_dfs = get_all_dfs(dataset, column)
        cleaned = distribute_time(all_dfs)
        for frame in cleaned:
            type = frame[frame.columns[1]].name
            ax.plot(frame['Time'], frame[type], '-o')

        ax.set_xticklabels(range(0, 16))
        # plt.xticks(np.arange(len(benign["Time"])), **label_font)
        plt.xticks(**label_font)
        plt.yticks(**label_font)
        plt.title(
            "Total Number of Unique IP Requests over HTTPS", **title_font)
        plt.xlabel("Time (in minutes)", **axis_font)
        plt.ylabel("Total Number of Unique IP Connections", **axis_font)
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(dataset_from, "dst ip")
    plt.savefig("./graphs/v2/https_unique_ip_responses_(" + app_name + ").png")


def frames_over_time(path, sheet, app_name):
    df = p.read_excel(path, index_col=None, sheet_name = sheet)
    df['timestamp'] = p.to_datetime(df['timestamp'], unit='s')
    df['Time'] = df["timestamp"].dt.strftime("%H:%M")

    def create_graph(dataset):
        dataset = dataset.groupby(['service', 'Time'])['frame size'].sum()
        dataset = dataset.to_frame()
        column = 'frame size'

        fig, ax = plt.subplots(figsize=(11, 7))
        all_dfs = get_all_dfs(dataset, column)
        cleaned = distribute_time(all_dfs)
        for frame in cleaned:
            type = frame[frame.columns[1]].name
            ax.plot(frame['Time'], frame[type], '-o')

        ax.set_xticklabels(range(0,16))
        plt.xticks(**label_font)
        plt.yticks(**label_font)
        plt.title("Total Traffic Sent over HTTPS", **title_font)
        plt.xlabel("Time (in minutes)", **axis_font)
        plt.ylabel("Total Traffic Sent (in bytes)", **axis_font)
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(df)
    plt.savefig("./graphs/v2/https_traffic_(" + app_name + ").png")

############################################
#                HTTP STUFF                #
############################################

def domains_over_time(path, sheet, app_name):
    df = p.read_excel(path, index_col=None, sheet_name=sheet)
    df['timestamp'] = p.to_datetime(df['timestamp'], unit='s')
    df['Time'] = df["timestamp"].dt.strftime("%H:%M")

    def create_graph(dataset):
        dataset = dataset.groupby(['service', 'Time'])['domain'].count()
        dataset = dataset.to_frame()
        column = 'domain'

        fig, ax = plt.subplots(figsize=(11, 7))
        service_types = list(dataset[column].index.levels[0])
        all_dfs = get_all_dfs(dataset, column)
        cleaned = distribute_time(all_dfs)
        for frame in cleaned:
            type = frame[frame.columns[1]].name
            ax.plot(frame['Time'], frame[type], '-o')

        ax.set_xticklabels(range(0, 16))
        # plt.xticks(np.arange(len(cleaned[0]['Time'])), **label_font)
        plt.xticks(**label_font)
        plt.yticks(**label_font)
        plt.title("Total Domain Requests/Responses over HTTP", **title_font)
        plt.xlabel("Time (in minutes)", **axis_font)
        plt.ylabel("Total Number of Domains", **axis_font)
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(df)
    plt.savefig("./graphs/v2/http_domain_number_(" + app_name + ").png")


ips_over_time("./results/new/games/Pandas/io.voodoo.paper2.apk.xlsx", "HTTPS", "io.voodoo.paper2.apk")
frames_over_time("./results/new/games/Pandas/io.voodoo.paper2.apk.xlsx", "HTTPS", "io.voodoo.paper2.apk")
domains_over_time("./results/new/games/Pandas/io.voodoo.paper2.apk.xlsx", "HTTP", "io.voodoo.paper2.apk")
