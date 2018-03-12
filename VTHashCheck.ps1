<#

.SYNOPSIS
Checks hash from VirusTotal.

.DESCRIPTION
VTHashCheck can determine whether a given hash is malicious or not. 
The hashes are sent to VirusTotal for analysis and the results are saved locally for future hash checks which enables for faster processing. 

A VirusTotal API Key will be required for this script to work.
Please visit https://www.virustotal.com/ > Settings > API Key

.PARAMETER File
Input file containing the hashes to be checked.

.PARAMETER VTApiKey
A Public/Private API Key from VirusTotal

.PARAMETER Output
Output file name.

.EXAMPLE
C:\VTHashCheck> .\VTHashCheck.ps1 -File .\hashes.csv -VTApiKey abc123 -Output fileName

.EXAMPLE
C:\VTHashCheck> .\VTHashCheck.ps1 -File .\hashes.txt -VTApiKey abc123 -Output fileName

.NOTES
Author : Sagar Kotian

#>


# ARGUMENTS AND SWITCHES
param(
	[parameter(Mandatory=$True)]
	# Input file containing the hashes to be checked.
	[string]$File,
	[parameter(Mandatory=$True)]
	# A Public/Private API Key from VirusTotal
	[string]$VTApiKey,
	[parameter(Mandatory=$True)]
	# Output file name
	[string]$Output
	)


#REGEX (SHA1, SHA256)
$regex = "[0-9a-fA-F]{40,64}"


# IMPORT HASHES FROM INPUT FILE
$Path = [System.IO.File]::ReadLines($File) | Select-String $regex -AllMatches | select -Expand Matches 


# PROGRESS BAR 1
for ($I = 1; $I -le $Path.Count; $I++ ){
	Write-Progress -Activity "Gathering Hashes : " -Status "$I hashes found" -id 1 
	$hashcount = $Path.Count
}


# HASH LIST PATH
$whitelistfile = ".\Hash-Lists\whitelist-hash.csv"
$blacklistfile = ".\Hash-Lists\blacklist-hash.csv"


#CREATES OUTPUT CSV
$csvHeaders = "Hash", "Comments"
$psObject = New-Object psobject

foreach($header in $csvHeaders)
{
 Add-Member -InputObject $psobject -MemberType noteproperty -Name $header -Value ""
}
$psObject | Export-Csv .\$Output.csv -NoTypeInformation



# COMPARES HASH
foreach($line in $Path){
	
    if($line -match $regex){
			
			$hash = $line
			
			# PROGRESS BAR 2
			$c++
			Write-Progress -Activity "Analysing Hash : $hash" -Status "$c of $hashcount" -id 2
			
			# CHECK IF HASH EXISTS IN WHITELIST
			$whitelist = Import-Csv -path $whitelistfile | Select -ExpandProperty Resource
			$whitehash = $whitelist | %{$_ -match $hash}
			
			# CHECK IF HASH EXISTS IN BLACKLIST
			$blacklist = Import-Csv -path $blacklistfile | Select -ExpandProperty Resource
			$blackhash = $blacklist | %{$_ -match $hash}
			
			# CHECK IF HASH EXISTS IN EXCLUSIONS
			$exclusion = Get-ChildItem .\Exclusions\ -Recurse -Force | Get-Content
			$excludehash = $exclusion | %{$_ -match $hash}
			
			
			# IGNORE IF EXISTS IN WHITELIST
			if($whitehash -contains $true){ 
				
				$wcom = "Clean"
				Write-Host "$hash : $wcom" -ForegroundColor DarkGreen
				
				$wo = @{"Hash"= $hash ; "Comments"=$wcom }
				$wnewRow = New-Object PsObject -Property $wo
				Export-Csv -path .\$Output.csv -inputobject $wnewrow -Append -Force
				
				}
				
			# IGNORE IF EXISTS IN BLACKLIST
			ElseIf($blackhash -contains $true){
				
				$bcom = "Malicious"
				Write-Host "$hash : $bcom" -ForegroundColor DarkRed
				
				$bo = @{"Hash"= $hash ; "Comments"=$bcom}
				$bnewRow = New-Object PsObject -Property $bo
				Export-Csv -path .\$Output.csv -inputobject $bnewrow -Append -Force
				
				}
			
			# IGNORE IF EXISTS IN EXCLUSION
			ElseIf($excludehash -contains $true){
				
				$ecom = "Excluded"
				Write-Host "$hash : $ecom" -ForegroundColor DarkGray 
				
				$exo = @{"Hash"= $hash ; "Comments"=$ecom}
				$enewRow = New-Object PsObject -Property $exo
				Export-Csv -path .\$Output.csv -inputobject $enewrow -Append -Force
				
				}
		

		Else {
			# SENDS HASH TO VIRUSTOTAL
			try{																																
			
				$body = @{ resource = $hash; apikey = $VTApiKey }
				$VTReport = Invoke-RestMethod -Method 'POST' -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $body
    
				# 15 sec. delay for public VT API keys. Comment out for private API Key.
				Start-Sleep -s 15
			}
			
			# CATCH EXCEPTIONS
			catch{																																							
				Write-Host "---------------------------------------------------------------------------------" -ForegroundColor Red
				If($_.Exception.Response.StatusCode -eq "403"){
				Write-Error "The VIRUSTOTAL API Key is invalid."
				}
				ElseIf($_.Exception.Response.StatusCode -eq "204"){
				Write-Error "Request rate limit exceeded. You are making more requests than allowed."
				}
				ElseIf($_.Exception.Response.StatusCode -eq "400"){
				Write-Error "Bad Request"
				}
				ElseIf($_.Exception.Response.StatusCode -eq $null){
				Write-Error "No response from Server. Check network connection"
				}
				Else{
				Write-Error "Error: " $_.Exception.Message "`n"
				}
				Write-Host "---------------------------------------------------------------------------------" -ForegroundColor Red
                Exit
			}
			
			# EXPORT CLEAN HASHES TO WHITELIST
			if ($VTreport.positives -eq 0){
				Write-Host "$hash : Clean" -ForegroundColor Green
				
				$vtw = [ordered]@{"Resource"= $VTReport.resource ; "Positives"= $VTReport.positives ; "Total"= $VTReport.total ; "Permalink"= $VTReport.permalink }
				$wlout =  New-Object PsObject -Property $vtw
				Export-Csv -path $whitelistfile -inputobject $wlout -Append -Force
				
				$vtout = [ordered]@{"Hash"= $VTReport.resource ; "Comments"="Clean" }
				$outfile =  New-Object PsObject -Property $vtout
				Export-csv -path .\$Output.csv -inputobject $outfile -Append -Force
			}
			
			# EXPORT MALICIOUS HASHES TO BLACKLIST 
			ElseIf ($VTreport.positives -gt 0){
                Write-Host $hash : "Malicious : "$VTreport.positives"engines detected this file" -ForegroundColor Red
				
				$vtb = [ordered]@{"Resource"= $VTReport.resource ; "Positives"= $VTReport.positives ; "Total"= $VTReport.total ; "Permalink"= $VTReport.permalink }
				$blout =  New-Object PsObject -Property $vtb
                Export-Csv -path $blacklistfile -inputobject $blout -Append -Force
				
				$vtout = [ordered]@{"Hash"= $VTReport.resource ; "Comments"="Malicious" }
				$outfile =  New-Object PsObject -Property $vtout
				Export-csv -path .\$Output.csv -inputobject $outfile -Append -Force
			}
			
			# HASHES WITH NO MATCH
			ElseIf ($VTreport.response_code -eq 0){
                Write-Host $hash : "No Matches found" -ForegroundColor White
				
				$vtout = [ordered]@{"Hash"= $VTReport.resource ; "Comments"="No Matches" }
				$outfile =  New-Object PsObject -Property $vtout
				Export-csv -path .\$Output.csv -inputobject $outfile -Append -Force
			}
		}
	}
	# CLEAR RAM
	[System.GC]::Collect()
}

# REMOVES DUPLICATE ENTRIES FROM HASH LISTS
function cleanup{

$wDup = Import-Csv -path $whitelistfile | Sort-Object * -Unique
$wDup | Export-Csv -path $whitelistfile -NoTypeInformation

$bDup = Import-Csv -path $blacklistfile | Sort-Object * -Unique
$bDup | Export-Csv -path $blacklistfile -NoTypeInformation
}
cleanup

	
# EXIT MESSAGE
Write-Host "`nResults exported to $Output.csv"
Write-Host "`nExiting...`n"