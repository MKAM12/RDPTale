


param (
 
 [string]$AbsPath

)

  
 if($AbsPath){
Write-Host "== Checking Windows Event logs for RDP Event Logs at: " $AbsPath "==`n`n"


 

  #*********Network Connection Attempts*********

  #check RDP Network Connection Attempts: Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
  #The first check is refering to successful network connection attempts as someone executed RDP to the target machine and it successfully responded and displayed a login window for the next step of entering credentials.

  write-Host "========Check RDP Connection Attempts======== `n"

  $file = Get-ChildItem $AbsPath  | 
                   Where {$_.Name -match "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"}

if($file){
[string] $file1 =[string]$AbsPath + "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx"

$Events = Get-WinEvent -FilterHashtable @{ Path =$file1; Id=261,1149} #filter events 261 and 1149 only
$EventsCSV = New-Object System.Collections.ArrayList					

ForEach ($Event in $Events) {   
	$eventXML = [xml]$Event.ToXml()   	# convert winevent to xml
	$datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format g # Convert the date and time to short format
	[void]$EventsCSV.Add($Event) # to be exported

	if($eventXML.Event.System.EventID -eq 261){ #Connection Attempts
		Write-Host "RDP Connection Attempt - Event ID[" $eventXML.Event.System.EventID "] `t at " $datetime}
     elseif ($eventXML.Event.System.EventID -eq 1149){ #Successful Connection Attempts
		Write-Host  "Sussccessful RDP Connection - Event ID[" $eventXML.Event.System.EventID "] `t at " $datetime " `t>> " "`tHost Name:" $eventXML.Event.System.Computer "`tRemote Hostname:"$eventXML.Event.UserData.EventXML.Param2 "`tRemote Source IP:" $eventXML.Event.UserData.EventXML.Param3  "`tUser Name:"$eventXML.Event.UserData.EventXML.Param1
		}
		
	}#end foreach

$Output1 = $AbsPath+ "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.csv"
$EventsCSV | Export-CSV -Path $Output1 #export to the same Log path
#add other option in the future :)

}
else {
write-host "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational Log File does Not Exist"}



 #*********Authentication Attempts*********
 
  write-Host "========Check RDP Successfull Authentication======== `n"

   $file = Get-ChildItem $AbsPath  | 
                   Where {$_.Name -match "Security.evtx"}

if($file){
[string] $file1 =[string]$AbsPath + "Security.evtx"

#Successfull RDP Login attempts

$Events = Get-WinEvent -FilterHashtable @{ Path =$file1; Id=4624,4625} | Where-Object {$_.properties[8].value -eq 10} #filter out RDP login attempts only
$EventsCSV = New-Object System.Collections.ArrayList
	
 ForEach ($Event in $Events) { 

    $eventXML = [xml]$Event.ToXml()   	# convert winevent to xml
    $datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format g #Convert the date and time to short format
    [void]$EventsCSV.Add($Event) # to be exported

    if($eventXML.Event.System.EventID -eq 4624){ #Successfull Logon
		Write-Host "successful RDP Authentication - Event ID(" $eventXML.Event.System.EventID ") `tSource:"$Event.properties[18].value "`tTarget Username:"$Event.properties[5].value "`t at " $datetime
    }elseif ($eventXML.Event.System.EventID -eq 4625){ #Failed Logon
        Write-Host "Failed RDP Authentication - Event ID(" $eventXML.Event.System.EventID ") `tSource:"$Event.properties[18].value "`tTarget Username:"$Event.properties[5].value "`t at " $datetime
    }
			
	}#End foreach


$Output2 = $AbsPath+ "Security.csv"
$EventsCSV | Export-CSV -Path $Output2	#export to the same Log path
#add other option in the future :)
}#end if
else {write-host "Security Log File does Not Exist"}



 #*********POST Authentication *********
write-Host "========Indicates successful RDP logon and session instantiation======== `n"

$file = Get-ChildItem $AbsPath  | Where {$_.Name -match "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"}

if($file){
[string] $file1 =[string]$AbsPath + "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"


$Events = Get-WinEvent -FilterHashtable @{ Path =$file1; Id=21}
$EventsCSV = New-Object System.Collections.ArrayList
	
ForEach ($Event in $Events) { 

  $eventXML = [xml]$Event.ToXml()   	# convert winevent to xml
  $datetime = Get-Date $eventXML.Event.System.TimeCreated.GetAttribute("SystemTime") -format g # Convert the date and time to short format
  [void]$EventsCSV.Add($Event) # to be exported

  if($eventXML.Event.UserData.EventXML.Address -ne "LOCAL"){
	 Write-Host "POST successful RDP Authentication - Event ID(" $eventXML.Event.System.EventID ") `tSource:"$eventXML.Event.UserData.EventXML.Address "`tTarget Username:"$eventXML.Event.UserData.EventXML.User "`t at " $datetime
   }
}


$Output3 = $AbsPath+ "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.csv"
$EventsCSV | Export-CSV -Path $Output3	# export the results to CSV file
#add other option in the future :)	
}
else {write-host "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational Log File does Not Exist"}

}else {write-host "Please specify the absolute path to all Windows Event logs (-AbsPath)"}
