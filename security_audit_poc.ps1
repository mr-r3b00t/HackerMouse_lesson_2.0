#HackerMouse Security Audit 1.0
#This script is to help stop Dr. Mousekechwitz and his gang of RATZ from steeling our Cheeses!

#Common attack vectors for ransomware involve Remote Desktop Protocol
#Things we can do to harden this...
#Check we have an account lockout policy configured
#Check if RDP is enabled
#Check the host based firewall for TCP 3389
#Check if NLA is enabled
#Enumerate the members of the administrators group and make sure not everyone is an admin

$ComputerName = "."
$riskrating = 0

#Enable RDP
#Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
#Disable RDP
#Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1

#Get Firewall status (profile)
Get-NetFirewallProfile
#Get Host Based Firewall config rules for Group 'Remote Desktop'
Get-NetFirewallRule -DisplayGroup "Remote Desktop"

$Check_RDP = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections"
write-host "Checking If RDP is enabled." -ForegroundColor Cyan
if($Check_RDP -eq 1){
write-host "Yaaas Cheese Threat level reduced!" -ForegroundColor Green}
else
{
Write-Host "Cheese Threat Level increased - RDP is enabled + 100 points" -ForegroundColor Red
$riskrating = $riskrating + 100
}


# Check if NLA is enabled
$Check_RDP_NLA = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $ComputerName -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired

write-host "RDP NLA Enabled: " $Check_RDP_NLA -ForegroundColor Cyan
if($Check_RDP_NLA -eq 1){
write-host "Yaaas Cheese Threat level reduced! -25 points" -ForegroundColor Green
$riskrating = $riskrating -25
}
else
{
Write-Host "Cheese Threat Level increased" -ForegroundColor Red
$riskrating = $riskrating + 100
}


# Setting the NLA information to Disabled
#(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $ComputerName -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

# Setting the NLA information to Enabled
#(Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $ComputerName -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(1)


#Get Local Admin Accounts
$admingroup = Get-LocalGroupMember -Group Administrators
write-host "Admin Group Count = " $admingroup.count -ForegroundColor Cyan
if($admingroup.count -ge 2){
write-host "High number of local admin users - Cheese threat level inceased + 25 points" -ForegroundColor Red
$riskrating = $riskrating + 25
}
else
{
write-host "Low number of local admin users - Cheese threat level reduced - 25 points" -ForegroundColor Green
$riskrating = $riskrating - 25
}
#Get Local Remote Desktop Users Accounts
$admingroup = Get-LocalGroupMember -Group "Remote Desktop Users"
write-host "RDP Group Count = " $admingroup.count -ForegroundColor Cyan
if($admingroup.count -ge 2){
write-host "High number of local RDP users - Cheese threat level inceased + 25 points" -ForegroundColor Red
$riskrating = $riskrating + 25
}
else
{
write-host "Low number of local RDP users - Cheese threat level reduced - 25 points" -ForegroundColor Green
write-host "HackerMouse must remember that local admins have RDP access by default" -ForegroundColor Cyan
$riskrating = $riskrating - 5
}

#now we need to contextualise the user objects because 
#Get Local Remote Desktop Users Accounts
$admingroup = Get-LocalGroupMember -Group "Remote Desktop Users"
write-host "RDP Group Count = " $admingroup.count -ForegroundColor Cyan
if($admingroup.count -ge 2){
write-host "High number of local RDP users - Cheese threat level inceased + 25 points" -ForegroundColor Red
$riskrating = $riskrating + 25
}
else
{
write-host "Low number of local RDP users - Cheese threat level reduced - 25 points" -ForegroundColor Green
write-host "HackerMouse must remember that local admins have RDP access by default" -ForegroundColor Cyan
$riskrating = $riskrating - 25
}



$UserResponse= [System.Windows.Forms.MessageBox]::Show("Do you backup the system?." , "Status" , 4)
if ($UserResponse -eq "YES" ) 
{
#Yes activity
    Write-host "Awesome, Hackermouse thinks it's great you have a backup!" -ForegroundColor Green
    $riskrating = $riskrating - 25
    $UserResponse= [System.Windows.Forms.MessageBox]::Show("Are the backups domain joined?." , "Status" , 4)
        if ($UserResponse -eq "YES" ) 
        {
        write-host "That doesn't sounds great! Hackermouse doesn't like domain joined backups as CheeseWare can encrypt all your files" -ForegroundColor Red
        $riskrating = $riskrating + 25
        #Yes activity
        } 
        else 
        {
        write-host "Great! It sounds like you have a backup and it's not domain joined!" -ForegroundColor Green
        $riskrating = $riskrating - 25
        #No activity
        }

} 
else 
{ 
        #No activity
        write-host "That doesn't sounds great! Hackermouse recomends you backup as CheeseWare can encrypt all your files" -ForegroundColor Red
        $riskrating = $riskrating + 100
}


write-host "Cheese Risk Rating = " $riskrating -ForegroundColor Red
