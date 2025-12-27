rule Trojan_Win32_SuspLocalData_A_2147955564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLocalData.A"
        threat_id = "2147955564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLocalData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "dir /b /s" ascii //weight: 1
        $x_1_3 = "Desktop" ascii //weight: 1
        $x_1_4 = "findstr /i" ascii //weight: 1
        $x_1_5 = "wallet" ascii //weight: 1
        $x_1_6 = "password" ascii //weight: 1
        $x_1_7 = "crypt" ascii //weight: 1
        $x_1_8 = "key" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_SuspLocalData_B_2147955565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLocalData.B"
        threat_id = "2147955565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLocalData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netstat.exe -na" ascii //weight: 1
        $x_1_2 = "ipconfig.exe /displaydns" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_SuspLocalData_C_2147955566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLocalData.C"
        threat_id = "2147955566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLocalData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Invoke-RestMethod -Uri" ascii //weight: 1
        $x_1_3 = "Out-File" ascii //weight: 1
        $x_1_4 = "$env:TMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

