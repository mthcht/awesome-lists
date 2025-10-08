rule Trojan_Win32_SusSysteminfo_MK_2147954091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusSysteminfo.MK"
        threat_id = "2147954091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusSysteminfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "systeminfo.exe" ascii //weight: 1
        $x_1_2 = "sysinfo.exe" ascii //weight: 1
        $x_1_3 = "whoami.exe" ascii //weight: 1
        $x_1_4 = "winver.exe" ascii //weight: 1
        $n_1_5 = "9453e881-26a8-4973-ba2e-76269e901d0z" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

