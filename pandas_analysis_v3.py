import pandas as p
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import time
import datetime
import math
from matplotlib import rcParams
rcParams.update({'figure.autolayout': True})
p.options.mode.chained_assignment = None

phone_ip = "192.168.137.186"
phone_ip2 = "192.168.137.46"
phone_ip3 = "192.168.137.21"
sns.set_style("darkgrid")
sns.set_context('talk')
sns.set_palette("Set1")

ALPHA = 0.7

title_font = {'fontname': 'Arial', 'size': '20', 'color': 'black', 'weight': 'normal',
              'verticalalignment': 'bottom'}  # Bottom vertical alignment for more space
axis_font = {'fontname': 'Arial', 'size': '16', 'color': 'black', 'weight': 'normal'}  # Bottom vertical alignment for more space
label_font = {'fontname': 'Arial', 'size': '12', 'color': 'black', 'weight': 'normal'}

all_apps = ["com.tubitv", "com.wayfair.wayfair", "io.voodoo.crowdcity", "com.sausageflip.game", "com.pinterest"]
# all_apps = ["io.voodoo.crowdcity"]
no_http = ["com.sausageflip.game"]

############################################
#               HELPER STUFF               #
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
    if 'ad' in service_types:
        ads = dataset[column]['ad'].reset_index().rename(
            columns={column: "Advertisements"})
        all_dfs.append(ads)
    if 'telemetry' in service_types:
        telemetry = dataset[column]['telemetry'].reset_index().rename(columns={
            column: "Tracking"})
        all_dfs.append(telemetry)

    # if 'tracking' in service_types:
    #     tracking = dataset[column]['tracking'].reset_index().rename(columns={
    #         column: "Tracking"})
    #     all_dfs.append(tracking)
    if 'ad,tracking' in service_types:
        both = dataset[column]['ad,tracking'].reset_index().rename(columns={
            column: "Both"})
        all_dfs.append(both)
    return all_dfs


def colour_lines(all_dfs):
    colours = []
    palette = sns.color_palette()
    for df in all_dfs:
        column = df.columns[1]
        if(column == "Benign"):
            colours.append(palette[2])
        elif(column == "Advertisements"):
            colours.append(palette[0])
        elif(column == "Tracking"):
            colours.append(palette[1])
        else:
            colours.append(palette[3])

    return colours


def clean_package_name(package_name):
    shortened = ""
    if(not p.isnull(package_name)):
        parts = package_name.split('.')
        if(parts[2] == 'apk'):
            shortened = parts[1]
        else:
            shortened = parts[1] + "." + parts[2]
        return shortened


def get_graph_name(sheet, app_name, graph_name):
    app_name = app_name.replace('.','-')
    if(sheet != ""):
        name = "./graphs/v3/" + app_name + "_" + graph_name + "(" + sheet + ").png"
    else:
        name = "./graphs/v3/" + app_name + "_" + graph_name + ".png"
    return name


############################################
#                HTTPS STUFF               #
############################################

def ips_over_time(path, sheet, app_name):
    df = p.read_excel(path, index_col=None, sheet_name=sheet)
    df['timestamp'] = p.to_datetime(df['timestamp'], unit='s')
    df['Time'] = df["timestamp"].dt.strftime("%H:%M")

    destination = df[(df['dst ip'] != phone_ip) & (df['dst ip'] != phone_ip2) & (df['dst ip'] != phone_ip3)]['dst ip']
    source = df[(df['src ip'] != phone_ip) & (df['src ip'] != phone_ip2) & (df['src ip'] != phone_ip3)]['src ip']
    both = (destination.append(source)).to_frame()
    both.sort_index(inplace=True)
    df.drop(['src ip', 'dst ip'], axis=1, inplace=True)
    # print(both)
    df['src/dst'] = both
   
    df = (df.groupby(['service', 'Time'])['src/dst'].nunique()).to_frame()

    def create_graph(dataset, column):
        fig, ax = plt.subplots(figsize=(11, 7))
        service_types = list(dataset[column].index.levels[0])
        all_dfs = get_all_dfs(dataset, column)
        cleaned = distribute_time(all_dfs)
        colours = colour_lines(cleaned)

        i = 0
        for frame in cleaned:
            type = frame[frame.columns[1]].name
            ax.plot(frame['Time'], frame[type], '-o', alpha=ALPHA, color=colours[i])
            i += 1

        ax.set_xticklabels(range(0, 16))
 
        plt.title("Total Number of Unique IP Connections over " +
                  sheet)
        plt.xlabel("Time (in minutes)")
        plt.ylabel("Total Number of Unique IP Connections")
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(df, "src/dst")
    # plt.show()
    plt.savefig(get_graph_name(sheet, app_name, "unique_ip_responses"))

    # get_graph_name(sheet, app_name, graph_name)


def frames_over_time(path, sheet, app_name):
    df = p.read_excel(path, index_col=None, sheet_name = sheet)
    df['timestamp'] = p.to_datetime(df['timestamp'], unit='s')
    df['Time'] = df["timestamp"].dt.strftime("%H:%M")

    def create_graph(dataset):
        column = 'frame size'
        dataset = dataset.groupby(['service', 'Time'])[column].sum()
        dataset = dataset.to_frame()

        fig, ax = plt.subplots(figsize=(11, 7))
        all_dfs = get_all_dfs(dataset, column)
        cleaned = distribute_time(all_dfs)
        colours = colour_lines(cleaned)

        i = 0
        for frame in cleaned:
            type = frame[frame.columns[1]].name
            ax.plot(frame['Time'], frame[type], '-o', alpha=ALPHA, color=colours[i])
            i += 1

        ax.set_xticklabels(range(0,16))

        plt.title("Total Traffic Sent over " + sheet)
        plt.xlabel("Time (in minutes)")
        plt.ylabel("Total Traffic Sent (in bytes)")
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(df)
    # plt.savefig("./graphs/v3/" + sheet + "_traffic_(" + app_name + ").png")
    plt.savefig(get_graph_name(sheet, app_name, "traffic"))


############################################
#                HTTP STUFF                #
############################################

def domains_over_time(path, sheet, app_name):
    df = p.read_excel(path, index_col=None, sheet_name=sheet)
    df['timestamp'] = p.to_datetime(df['timestamp'], unit='s')
    df['Time'] = df["timestamp"].dt.strftime("%H:%M")

    def create_graph(dataset):
        dataset = dataset.groupby(['service', 'Time'])['domain'].nunique()
        dataset = dataset.to_frame()
        column = 'domain'

        fig, ax = plt.subplots(figsize=(11, 7))
        service_types = list(dataset[column].index.levels[0])
        all_dfs = get_all_dfs(dataset, column)
        cleaned = distribute_time(all_dfs)
        colours = colour_lines(cleaned)

        i = 0
        for frame in cleaned:
            type = frame[frame.columns[1]].name
            ax.plot(frame['Time'], frame[type], '-o', alpha=ALPHA, color=colours[i])
            i += 1

        ax.set_xticklabels(range(0, 16))

        plt.title("Total Domain Connections over "  + sheet)
        plt.xlabel("Time (in minutes)")
        plt.ylabel("Total Domains Connections")
        ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
        plt.legend(fontsize=12)

    create_graph(df)
    # plt.savefig("./graphs/v3/" + sheet + "_domain_number_(" + app_name + ").png")
    plt.savefig(get_graph_name(sheet, app_name, "domain_number"))


def https_vs_http(path, app_name):
    http = p.read_excel(path, index_col=None, sheet_name='HTTP')
    https = p.read_excel(path, index_col=None, sheet_name='HTTPS')

    http['timestamp'] = p.to_datetime(http['timestamp'], unit='s')
    https['timestamp'] = p.to_datetime(https['timestamp'], unit='s')
    http['Time'] = http["timestamp"].dt.strftime("%H:%M")
    https['Time'] = https["timestamp"].dt.strftime("%H:%M")
    http = http.groupby(['Time'])['frame size'].sum().to_frame().reset_index()
    https = https.groupby(['Time'])['frame size'].sum().to_frame().reset_index()
    http.columns = ['Time', 'HTTP Frame Size']
    https.columns = ['Time', 'HTTPS Frame Size']

    http, https = distribute_time([http, https])
    both = http.merge(https)

    fig, ax = plt.subplots(figsize=(11, 7))

    both.plot(ax=ax, secondary_y=['HTTPS Frame Size'], style='-o', alpha=ALPHA)
    plt.title("HTTP Traffic VS HTTPS Traffic over Time")
    ax.set_xlabel("Time (in minutes)")
    ax.set_ylabel('Total Traffic over HTTP (in bytes)')
    ax.right_ax.set_ylabel('Total Traffic over HTTPS (in bytes)')
    ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
    ax.right_ax.yaxis.set_major_formatter(plt.FormatStrFormatter('%d'))
    ax.set_xticklabels(range(0, 16))
    ax.set_xticks(range(0, 16))

    lines = ax.get_lines() + ax.right_ax.get_lines()
    ax.legend(lines, [l.get_label() for l in lines], loc='upper right', fontsize=12)
    
    # plt.savefig("./graphs/v3/http_vs_https_(" + app_name + ").png")
    plt.savefig(get_graph_name("", app_name, "http_vs_https"))
    # plt.show()


def benign_domains(path, app_name):
    df = p.read_excel(path, index_col=None, sheet_name='HTTPS')
    benign = df[df['service'] == 'benign']
    benign = benign[benign.domain.notnull()]
    print(benign)

############################################
#               EITHER STUFF               #
############################################

def get_all_domains(path, app_name):
    df = p.read_excel(path, index_col=None, sheet_name='HTTP')
    df2 = p.read_excel(path, index_col=None, sheet_name='HTTPS')

    all_domains = list(df['domain'].dropna()) + list(df2['domain'].dropna())

    domain_class1 = df[['domain', 'service']]
    domain_class2 = df2[['domain', 'service']]
    domain_class = (domain_class1.append(domain_class2)).drop_duplicates().reset_index()
    domain_class.drop(['index'], axis=1, inplace=True)

    domain_dict = {}
    for domain in all_domains:
        if domain in domain_dict:
            domain_dict[domain] += 1
        else:
            domain_dict[domain] = 1

    df = p.DataFrame.from_dict(domain_dict, orient='index')
    df.reset_index(inplace=True)
    df.columns = ['domain','Count']
    df = df.merge(domain_class)
    df.columns = ['Domain', 'Count', 'Service']
    df.sort_values(by='Count', inplace=True, ascending=False)
    df.set_index('Domain', inplace=True)
    # print(df.head(10))
    print(df.head(10).to_latex())


def sum_domain(path, app_name, domain):
    df_http = p.read_excel(path, index_col=None, sheet_name="HTTP")
    df_https = p.read_excel(path, index_col=None, sheet_name="HTTPS")
    both = df_http.append(df_https)
    domain_df = both[both['domain'] == domain]
    print(sum(domain_df['frame size']))

def non_benign_domains(path, app_name):
    df_http = p.read_excel(path, index_col=None, sheet_name="HTTP")
    df_https = p.read_excel(path, index_col=None, sheet_name="HTTPS")
    both = df_http.append(df_https)
    both.drop((both[both['service'] == 'benign'].index), inplace=True)

    both = both.groupby('domain')['frame size'].sum()
    both.sort_values(inplace=True, ascending=False)
    print(both.head(10))

############################################
#              SUMMARY STUFF               #
############################################

def compare_ips_to_domains():
    cols = ['Package Name', 'Benign Domains', 'Benign IPs', 'Ad Domains', 'Ad IPs', 'Tracking Domains', 'Tracking IPs']
    df = p.read_csv('./make_it_stop/Pandas/game_summary.csv', index_col=None, usecols=cols)

    def count_domains(domain_string):
        if(p.isnull(domain_string)):
            count = 0
        else:
            count = len(domain_string.split(','))
        return count

    def should_drop(row):
        drop = False
        a = row['Benign Domain Count'] == 0
        b = row['Ad Domain Count'] == 0
        c = row['Tracking Domain Count'] == 0
        d = row['Benign IPs'] == 0
        e = row['Ad IPs'] == 0
        f = row['Tracking IPs'] == 0
        if(a and b and c and d and e and f):
            drop = True
        return drop

    df['Benign Domain Count'] = list(map(lambda x: count_domains(x), df['Benign Domains']))
    df['Ad Domain Count'] = list(map(lambda x: count_domains(x), df['Ad Domains']))
    df['Tracking Domain Count'] = list(map(lambda x: count_domains(x), df['Tracking Domains']))
    df.drop('Benign Domains', axis=1, inplace=True)
    df.drop('Ad Domains', axis=1, inplace=True)
    df.drop('Tracking Domains', axis=1, inplace=True)

    df['Should Drop'] = df.apply(should_drop, axis=1)
    df = df.drop(df[df['Should Drop']].index)
    df.drop('Should Drop', axis=1, inplace=True)

    df['Package Name'] = list(map(lambda x: clean_package_name(x), df['Package Name']))
    df.set_index('Package Name', inplace=True)
    df = df[['Benign IPs', 'Benign Domain Count', 'Ad IPs', 'Ad Domain Count', 'Tracking IPs', 'Tracking Domain Count']]

    ax = df.plot(kind='bar', stacked=False, figsize=(16, 5), rot=0, width=0.8)
    plt.show()


def compare_confirmed_to_suspected():
    cols = ['Package Name', 'Suspected Ad IPs', 'Ad IPs', 'Suspected Tracking IPs', 'Tracking IPs']
    renamed = ['HTTP Ad IPs', 'HTTPS Ad IPs', 'HTTP Tracking IPs', 'HTTPS Tracking IPs']
    df = p.read_csv('./make_it_stop/Pandas/game_summary.csv', index_col=None, usecols=cols)

    df['Package Name'] = list(map(lambda x: clean_package_name(x), df['Package Name']))
    df.set_index('Package Name', inplace=True)
    df = df[cols[1:]]
    df.columns = renamed

    current_palette = sns.color_palette()
    fig, ax = plt.subplots(figsize=(11,7))
    df[[renamed[0], renamed[2]]].plot.bar(ax=ax, stacked=True, position=1, width=0.4, color=current_palette[0:2])
    df[[renamed[1], renamed[3]]].plot.bar(ax=ax, stacked=True, position=0, width=0.4, color=current_palette[2:4])

    plt.title("HTTP versus HTTPS Advertisement and Tracking IPs")
    plt.xlabel("Application")
    plt.ylabel("Total Number of IPs")

    plt.savefig("./graphs/v3/suspected_vs_confirmed_ips.png")
    # plt.show()


# for app in all_apps:
#     print(app)
#     ips_over_time("./make_it_stop/Pandas/" + app + ".apk.xlsx", "HTTPS", app)
#     frames_over_time("./make_it_stop/Pandas/" + app + ".apk.xlsx", "HTTPS", app)
#     domains_over_time("./make_it_stop/Pandas/" + app + ".apk.xlsx", "HTTPS", app)
#     https_vs_http("./make_it_stop/Pandas/" + app + ".apk.xlsx", app)

#     if(app not in no_http):
#         ips_over_time("./make_it_stop/Pandas/" + app + ".apk.xlsx", "HTTP", app)
#         frames_over_time("./make_it_stop/Pandas/" + app + ".apk.xlsx", "HTTP", app)
#         domains_over_time("./make_it_stop/Pandas/" + app + ".apk.xlsx", "HTTP", app)
    
#     plt.close('all')

# sum_domain("./make_it_stop/Pandas/" + all_apps[4] + ".apk.xlsx", all_apps[4],
#            "ct.pinterest.com")

non_benign_domains("./make_it_stop/Pandas/" + all_apps[4] + ".apk.xlsx", all_apps[4])

# get_all_domains("./make_it_stop/Pandas/" +  all_apps[4] + ".apk.xlsx",  all_apps[4])

# compare_ips_to_domains()
# compare_confirmed_to_suspected()

# benign_domains("./make_it_stop/Pandas/io.voodoo.paper2.apk.xlsx", "io.voodoo.paper2")



