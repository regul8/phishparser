__author__ = 'Jeremy Trinka'
# -- PhishParser 1.0 by Jeremy Trinka
# -- Parses GET requests to run statistics against
# -- a provided spreadsheet for phishing
# -- exercises.  Used in conjunction with IIS and
# -- HMailServer.

import os
import sys
import re
import shutil
import glob
import csv
##import pandas

# Find-Between function to pull the GET requests.

def find_between( s, first, last ):
    try:
        start = s.index( first ) + len( first )
        end = s.index( last, start )
        return s[start:end]
    except ValueError:
        return ""

# Finds the number of rows in a file
def file_len(fname):
    i = 0
    with open(fname) as file:
        for line in file:
            i += 1
        return i

# Choose the name of this phishing exercise.  Example: "ABC-01-01-PHISH01"
# The name selected here is reflected when creating directories.

projName = ""

# Set global directory variables.

getLogDir = ""
getCSVDir = ""

#######################
# Sanitize User Input #
#######################

sanitizeName = False
while sanitizeName is False:
    projName = raw_input("What is the name of this exercise? [No spaces or slashes]: ")
    # Test if the string is empty.  If yes, quit.
    if not projName:
        print("Project name is empty.  Try again.")
    # Test if the string has spaces.  If yes, quit.
    elif re.search(r'[\s]', projName):
        print("Project name has spaces.  Try again.")
    # Test if string has backslash.  If yes, quit.
    elif re.search(r'\\', projName):
        print("Project name has backslashes.  Try again.")
    # Test if string has forward slash.  If yes, quit.
    elif re.search(r'\/', projName):
        print("Project name has backslashes.  Try again.")
    # Input has been properly sanitized.  Create deposit for log file and CSV.
    else:
        if not (os.path.exists(projName + '_LOGS') and os.path.exists(projName + "_CSV")):
            print("Creating project \"" + str(projName) + "\"...")
            # Get and print log file working directory.
            os.makedirs(projName + '_LOGS')
            os.chdir(projName + '_LOGS')
            getLogDir = os.getcwd()
            os.chdir("..")
            # Get and print CSV working directory.
            os.makedirs(projName + "_CSV")
            os.chdir(projName + "_CSV")
            getCSVDir = os.getcwd()
            os.chdir("..")
            # Inform the user.
            print("[*] Directory \"" + str(getLogDir) + "\" created.  Please drop ALL logs here...")
            print("[*] Directory \"" + str(getCSVDir) + "\" created.  Please drop ONE reference CSV here...")
            print("[*] !! PLEASE MAINTAIN A BACKUP OF ALL DATA PLACED IN THESE DIRECTORIES !!")
            # Wait for user to hit enter to resume program.
            raw_input('[*] Please press [ENTER] when files have been copied...')
##            # Check if directories contain files.  If not, reverse...
##            if os.listdir(getLogDir) == [] or os.listdir(getCSVDir) == []:
##                print('One or more directories is empty.  Exiting...')
##                shutil.rmtree(getLogDir)
##                shutil.rmtree(getCSVDir)
##                sys.exit()
##            # End sanitization loop.
            sanitizeName = True
        else:
            # Directories exist, result in hard exit.
            print("Project exists.  Exiting...")
            sys.exit()
#############################
# Initiate Log File Cleanup #
#############################

# Combine the contents of the log files.
concatLogFile = projName + '_concat.txt'
os.chdir(getLogDir)
with open(concatLogFile, 'wb') as outfile:
    for filename in glob.glob('*.log'):
        if filename == concatLogFile:
            continue
        with open(filename, 'rb') as readfile:
            shutil.copyfileobj(readfile, outfile)

# Extract the GET requests.
getCleanup = projName + '_cleanup.txt'
cleanupOutfile = open(getCleanup, 'wb')
with cleanupOutfile as outfile:
    with open(concatLogFile, 'rb') as readfile:
        for line in readfile:
            outfile.write(find_between( line, "GET /", " - 80" ) + '\n')

# Clean up blank lines and bad GET requests.
getFinal = projName + '_final.txt'
finalOutfile = open(getFinal, 'wb')
with finalOutfile as outfile:
    with open(getCleanup, 'rb') as readfile:
        for line in readfile:
            line = line.rstrip()
            # Skip lines that are blank
            if line != '':
                # Create a list of extensions and characters that aren't going to be used for valid responses
                # and skip the line items in the final output file.
                badChars = [".jpg", ".png", ".css", ".ico", "/", ".jsp", ".php", ".txt", ".xml", ".js", "muieblackcat", ":", "@"]
                if not any(word in line for word in badChars):
                    # Write the new lines...
                    outfile.write( line + '\n')

# Remove unnecessary files
os.remove(concatLogFile)
os.remove(getCleanup)

# Create the RESULTS directory.
os.makedirs('..\\' + projName + '_RESULTS')
os.chdir('..\\' + projName + '_RESULTS')
resultsDir = os.getcwd()
os.chdir('..')

# Move the reference CSV and rename it.
os.chdir(getCSVDir)
for filename in glob.glob('*.csv'):
    os.rename(filename, 'referencesheet.csv')
    shutil.copy('referencesheet.csv', resultsDir)

# Move the reference GET requests and return to RESULTS folder.
os.chdir(getLogDir)
os.rename(getFinal, 'referencelist.csv')
shutil.copy('referencelist.csv', resultsDir)
os.remove('referencelist.csv')
os.chdir(resultsDir)

######################################
# Initiate CSV Comparator Operations #
######################################

refLog = 'referencelist.csv'
refCSV = 'referencesheet.csv'

writeResultsStats = open(projName + '_RESULTS.txt', 'wb')
writeResultsCSV = open(projName + '_RESULTS.csv', 'wb')

with open(refLog, 'rb') as csvfile1:
    with open(refCSV, 'rb') as csvfile2:
        with writeResultsCSV as outfile:
            writer = csv.writer(outfile)
            # Set up the new CSV header file and write it out
            writeHead = csv.DictWriter(outfile, fieldnames = ["GetKey","EID","Name","Business Title","Email Address","Supervisor EID","Supervisor Name","Supervisor Business Title","Supervisor Email Address","Location","City","State","Dept ID","Dept Name","Line of Busines","Clicks"], delimiter = ',')
            writeHead.writeheader()
            # Set the reader files
            reader1 = csv.reader(csvfile1) # The cleaned up logfile GETs
            reader2 = csv.reader(csvfile2) # The reference CSV file
            # Set the target of the logfiles as the "first column"
            rows1_col_a = [row[0] for row in reader1]
            # Set the target of the reference CSV as the first column
            rows2 = [row for row in reader2]
            # For each row in the CSV file, check if the item in the 0th column is in the
            # cleaned up log file.  If it is, write it out to the new results file.
            hitCounter = 0
            for row in rows2:
                # If row 0 value is in the reference file
                if row[0] in rows1_col_a:
                    # Check the number of clicks
                    data = open(refLog).readlines()
                    for line in data:
                        if str(row[0]) in line:
                            # Set the occurance as hitCounter
                            hitCounter += 1
                    # Append the hit counter to "Clicks" and write it out to the new CSV
                    row.append(hitCounter)
                    writer.writerow(row)
                    hitCounter = 0

# Shut em down open up shop
csvfile1.close()
csvfile2.close()

#################
# Run the Stats #
#################

totalRef = file_len(refCSV) - 1
totalClickers = file_len(projName + '_RESULTS.csv') - 1
failPercent = float(totalClickers) / float(totalRef) * 100.00
passPercent = 100.00 - float(failPercent)

## Get the total number of Clicks from RESULTS CSV
##resultsCSV = pandas.read_csv(projName + '_RESULTS.csv')
##totalClicks = resultsCSV[resultsCSV.columns[15:]].sum()

## Get total reference assuming first line of the CSVs is a header

with writeResultsStats as outfile:
    outfile.write("Exercise " + projName + " Results:" + '\n')
    outfile.write("-- Total Tested: " + str(totalRef) + '\n')
    outfile.write("-- Total Failed: " + str(totalClickers) + '\n')
##    outfile.write("-- Total Clicks: " + str(totalClicks) + '\n')
    outfile.write("-- Percent Fail: " + str(failPercent) + "%" + '\n')
    outfile.write("-- Percent Pass: " + str(passPercent) + "%" + '\n')

# Cleanup

os.remove('referencelist.csv')
os.remove('referencesheet.csv')

print ("[*] ...DONE!  You can find the results for this exercise in: " + resultsDir)