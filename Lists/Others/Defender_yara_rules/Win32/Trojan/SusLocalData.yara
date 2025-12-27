rule Trojan_Win32_SusLocalData_A_2147954103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusLocalData.A"
        threat_id = "2147954103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusLocalData"
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
        $n_1_9 = "a453e881-26a8-4973-bm2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (5 of ($x*))
}

rule Trojan_Win32_SusLocalData_B_2147954104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusLocalData.B"
        threat_id = "2147954104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusLocalData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netstat.exe -na" ascii //weight: 1
        $x_1_2 = "ipconfig.exe /displaydns" ascii //weight: 1
        $n_1_3 = "a453e881-26a8-4973-bn2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_SusLocalData_C_2147954105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusLocalData.C"
        threat_id = "2147954105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusLocalData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Invoke-RestMethod -Uri" ascii //weight: 1
        $x_1_3 = "Out-File" ascii //weight: 1
        $x_1_4 = "$env:TMP" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bo2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

