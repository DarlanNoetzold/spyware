import csv
path = r"C:\Windows\System32\drivers\etc\hosts"
redirect = "127.0.0.1"
websites = []
with open('sites.csv') as file:
    read_csv = csv.reader(file)
    for row in read_csv:
        websites.append(row[0])
with open(path, 'r+') as file:
    content = file.read()
    for site in websites:
        if site in content:
            pass
        else:
            file.write(redirect + " " + site + "\n")