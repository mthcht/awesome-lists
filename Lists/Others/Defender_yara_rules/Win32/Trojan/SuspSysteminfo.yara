rule Trojan_Win32_SuspSysteminfo_MK_2147955556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSysteminfo.MK"
        threat_id = "2147955556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSysteminfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systeminfo.exe" ascii //weight: 1
        $x_1_2 = "sysinfo.exe" ascii //weight: 1
        $x_1_3 = "whoami.exe" ascii //weight: 1
        $x_1_4 = "winver.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

