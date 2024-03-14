
# NoWhere2Hide Active Scanner

![](.images/banner.png)

***NoWhere2Hide*** is an open-source active scanner tailored for security researchers and professionals keen on investigating Command and Control (C2) infrastructures. Developed in GO, it leverages ZGRAB2 for scanning and utilizes a PostgreSQL database for storing scan data and detecting C2s.

NoWhere2Hide empowers threat researchers to pinpoint malicious infrastructures, craft C2 signatures, and continually monitor and authenticate C2s. It promotes innovative approaches to identifying malicious infrastructures, steering away from scanning the entire internet, and offers a structured format and framework for exchanging C2 signatures within our community.

My ultimate aim is to facilitate the effortless creation of detection signatures and their dissemination within the community for mutual scanning and detection. 

That being said, I've also tailored this tool for individuals like myself who conduct or aspire to conduct their own scanning activities, without necessarily having the means or inclination to share their signatures publicly.

C2links4life

# Installation Overview

Tested and validated on Ubunutu 22.04, but should work wherever GO and Postgres can be installed.

## Install GO

Follow instructions -> https://go.dev/doc/install

## Clone Project

git clone https://github.com/c2links/NoWhere2Hide.git

## Install and Setup Postgres

```
sudo apt update
sudo apt install postgresql postgresql-contrib

<nowhere2hide>
y

sudo -u postgres psql -c "ALTER USER nowhere2hide PASSWORD 'nowhere2hide';"
sudo -u postgres createdb nowhere2hide
```

# Run

To build and run, enter the below commands

```
go build .
./main
```

Navigate to http://localhost:6332 to get to the UI.

You can additionally set the port to use by supplying the port as a argument `./main -port 12345` 

By default the signatures are located in the folder, "../signatures", but this can also be changed by supplying the "signatures argument, `./main -signatures <path to signatures>`

# Overview

Please see below for more details on how to use NoWhere2Hide. There are 5 main functions of NoWhere2Hide.

1. View detected C2's: Go here to see the C2's you have detected organized by malware family
2. Run a scan: Go here to run a scan based on one of the signatures you have created. Or one of the pre-built scans.
3. View scan results separated by scan results
    * Banner
    * HTTP
    * TLS
    * JARM
4. Create / Edit Signatures
5. Administration
    * Clear database
    * View logs (Future)
    * Readme

# Creating Your First Signature

Coming Soon

## Run your Scan
Coming Soon


## View Results
Coming Soon


## Modify Signature Add Detection
Coming Soon

## Reload Detections
Coming Soon


# View Detected C2's

Here you can click on any Malware Family to view the current list of C2's for that family.

The C2's are the result of the PostGres queries defined in the created signature (See above). There should be no duplicates in this list, when the C2 database is populated, if the same IP:PORT:Malware_Family combination already exists, the last scan time is modified, but a new entry is not created.

![](.images/c2_results.png)








