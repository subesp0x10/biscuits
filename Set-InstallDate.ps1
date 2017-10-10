param([string]$date)

$new_date = [DateTime]::ParseExact($date,'yyyyMMddHHmmss',$null)
$new_date_utc = $new_date.ToUniversalTime()

$b = [DateTime]::ParseExact("19700101000000",'yyyyMMddHHmmss',$null)

$c = (New-TimeSpan -Start $b -End $new_date_utc).TotalSeconds

$reg_path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

Set-ItemProperty -Path $reg_path -Name InstallDate -Value $c -type DWORD


