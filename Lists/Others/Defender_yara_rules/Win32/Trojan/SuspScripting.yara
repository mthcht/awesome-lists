rule Trojan_Win32_SuspScripting_MK_2147955551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspScripting.MK"
        threat_id = "2147955551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScripting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockLess.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "WebCacheV01.dat" ascii //weight: 1
        $x_1_4 = "taskhostw" ascii //weight: 1
        $x_1_5 = "out.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_SuspScripting_A_2147955552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspScripting.A"
        threat_id = "2147955552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspScripting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c Unblock-File" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "Invoke-Sysinfo" ascii //weight: 1
        $x_1_4 = "Import-Module" ascii //weight: 1
        $x_1_5 = "-PsHistory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

