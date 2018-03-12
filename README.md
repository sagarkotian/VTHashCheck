# VTHashCheck
VTHashCheck can determine whether a given hash is malicious or not. The hashes are sent to VirusTotal for analysis and the results are saved locally for future hash checks which enables for faster processing. 


## Getting Started

### VirusTotal API Key

A **VirusTotal API Key** will be required to run this script. VirusTotal's API will let you submit the hashes to the servers for analysis.

To find your API Key:
- Login to https://www.virustotal.com
- Click on the user image > Settings > API Key

>**Note:** VirusTotal allows only four requests per minute for the Public API Key. Kindly comment out the 15sec delay in case of Private API.



### Exclusions Folder
Any hashes saved in this folder will be excluded from checks. 
The hashes can be save in a .txt/.csv format.

### Hash-Lists Folder
This contains the list of malicious and clean hashes from previous analysis, which will save time and bandwidth for future use.



## Parameters

**-File**  Input file containing the (SHA1/SHA256)hashes to be checked. The file could be of any file format (.txt/.csv). 

**-VTApiKey** A Public/Private API Key from VirusTotal.

**-Output** Output file name. The results will be saved in a .csv format.



## Usage
`PS C:\VTHashCheck> .\VTHashCheck.ps1 -File .\hashes.csv -VTApiKey YOURAPIKEY -Output fileName`

**Help:**
`PS C:\VTHashCheck> Get-Help .\VTHashCheck.ps1`
