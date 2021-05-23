# Powershell Commands
## Basic Stuff

Powershell version of `ls -al`. Print everything in the directory.
```powershell
gci -fo
gci -force
```
```powershell
Get-ChildItem -Force
```

Print file content
```powershell
gc filename.txt
Get-Content –Path filename.txt
```
```powershell
type filename.txt
more filename.txt
```

First X lines (like top on linux)
```powershell
Get-Content ".\file_test.txt" | select -First 10
```

Alternate Data Stream

```powershell
Get-Item –Path C:\users\cyborg8\desktop\* -Stream *

Get-Content –Path C:\users\cyborg8\desktop\some_file.exe -Stream zone.identifier
```


Base64 decode
```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("YwB5AGIAZQByAGcAZQBkAGQAbwBuAA=="))
```

Base64 encode

```powershell
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("yoho text to encode"))
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("yoho text to encode"))
```

Hash a string or file
```powershell
| Get-Hash -Algorithm MD5

Get-FileHash <filepath> -Algorithm MD5
```

Sort list. Get unique elements in list.

```powershell
| Sort-Object | Get-Unique
```

## Enumeration


Hosts file location

```powershell
C:\Windows\System32\drivers\etc\hosts
```

Also other interesting files in that etc folder.


Show domain info

```powershell
Get-ADDomain
```

Find AD computers in domain
```powershell
get-adcomputer -Filter 'enabled -eq "true"'
get-adcomputer -Filter 'ObjectClass -eq "computer"'

Get-ADComputer -Filter * -Property Name,Description | Select -Property Name,Description
```

Get description for AD computer
```powershell
Get-ADComputer -Filter * -Property Name,Description | Select -Property Name,Description
```

Show all AD users

```powershell
net user
Get-ADUser -Filter *
```

Find user and show properties

```powershell
Get-ADUser -Filter 'Name -like "*chris*"'
Get-ADUser -Filter 'Name -like "*chris*"' -Properties *
Get-ADUser -Filter 'Name -like "*chris*"' -Properties State

get-aduser -filter * -Property * | Where-Object {$_.mobile -eq "876-5309"} | Format-Table
get-aduser -filter * -Property * | Where-Object {$_.phoneNumber -eq "876-5309"} | Format-Table
get-aduser -filter * -Property * | Where-Object {$_.telephoneNumber -eq "876-5309"} | Format-Table
```

Find user with certain property (property exists)
```powershell
get-aduser -filter * -Property LogonHours | Where-Object {$_.LogonHours -ne $null} | Format-List
```



Find user group
```powershell
Get-ADGroup -Filter 'Name -like "cyborg"'
```

List users in group
```powershell
Get-ADGroup -Filter 'Name -like "cyborg"' | Get-ADGroupMember
```

Count users in group
```powershell
(Get-ADGroup -Filter 'Name -like "cyborg"' | Get-ADGroupMember).count
```


Show services
```powershell
Get-Service
```

Find service by Name

```powershell
Get-Service -Name *update*
```

Find service by DisplayName

```powershell
Get-Service -DisplayName *update*
```

Service details
```powershell
Get-WMIObject -Class Win32_DCOMApplicationSetting -Filter "AppId='{59B8AFA0-229E-46D9-B980-DDA2C817EC7E}'"
```


Show full powershell version table with build version:

```powershell
echo $PSVersionTable
$PSVersionTable
```

Show only powershell version:

```powershell
$PSVersionTable.PSVersion
$host.Version
(Get-Host).Version
```

Applocker policy

```powershell
$xml = [xml](Get-AppLockerPolicy -Effective -Xml)
$xml.AppLockerPolicy.RuleCollection | select -ExpandProperty childnodes 
```


DNS zone aging
```powershell
Get-DnsServerZoneAging -Name underthewire.tech
```


## Cmdlets

Find cmdlet name for alias

```powershell
get-command *wget*
```


## File Manipulations


Grep-style find lines with string pattern in file
```powershell
Select-String -Path "u_ex160413.log" -Pattern "password"   
```


Find files by filename (case insensitive)

```powershell
Get-ChildItem C:\users\century7\ -Recurse -Filter *readme*
```


Find hidden files

```powershell
Get-ChildItem -ErrorAction SilentlyContinue -Exclude desktop.ini -Recurse -Attributes !D+H
```

Include hidden files in regular search
```powershell
Get-ChildItem -Recurse -Hidden
```


Count number of files in directory

```powershell
Get-ChildItem C:\users\century3\desktop -Recurse -File | Measure-Object | %{$_.Count}
```

Count number of directories in directory

```powershell
Get-ChildItem C:\users\century6\desktop -Recurse -Directory | Measure-Object | %{$_.Count}
```


Print line 160 from file
```powershell
Get-Content C:\users\century9\desktop\Word_File.txt | Select -Index 160
```


Print word 160 from line
```powershell
$teststring = Get-Content C:\users\century9\desktop\Word_File.txt
($teststring -split " ")[160]
```

Count characters in string / file
```powershell
$teststring = Get-Content C:\users\century13\desktop\countmywords
($teststring -split " ").length
```


Find number of occurances of word
```powershell
$a = Get-Content -Path .\Desktop\words.txt | Select-String -Pattern beetle -AllMatches
$a.Matches.Count
```