rule Trojan_Win32_SusPrivChecks_A_2147955608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivChecks.A"
        threat_id = "2147955608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivChecks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "Invoke-PrivescCheck" ascii //weight: 1
        $x_1_5 = "Import-Module" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusPrivChecks_B_2147955609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivChecks.B"
        threat_id = "2147955609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivChecks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "Get-WinUpdates" ascii //weight: 1
        $x_1_5 = "Import-Module" ascii //weight: 1
        $x_1_6 = "-ComputerName localhost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusPrivChecks_C_2147955610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivChecks.C"
        threat_id = "2147955610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivChecks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe query" ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusPrivChecks_D_2147955611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivChecks.D"
        threat_id = "2147955611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivChecks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "logicaldisk" ascii //weight: 1
        $x_1_3 = "freespace" ascii //weight: 1
        $x_1_4 = "caption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

