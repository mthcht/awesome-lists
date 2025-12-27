rule Trojan_Win32_SusScripting_MK_2147954086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusScripting.MK"
        threat_id = "2147954086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusScripting"
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
        $n_1_6 = "9453e881-26a8-4973-ba2e-76269e901d0u" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (4 of ($x*))
}

rule Trojan_Win32_SusScripting_A_2147954087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusScripting.A"
        threat_id = "2147954087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusScripting"
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
        $n_1_6 = "9453e881-26a8-4973-ba2e-76269e901d0v" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (4 of ($x*))
}

