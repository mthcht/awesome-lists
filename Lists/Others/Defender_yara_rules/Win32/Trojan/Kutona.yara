rule Trojan_Win32_Kutona_2147931163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kutona!dha"
        threat_id = "2147931163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kutona"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Parent PID: %u ..." ascii //weight: 1
        $x_1_2 = "SUCCESS ..." ascii //weight: 1
        $x_1_3 = "FAILED ..." ascii //weight: 1
        $x_1_4 = "IsMenu" ascii //weight: 1
        $x_1_5 = "Industry" ascii //weight: 1
        $x_1_6 = "%SYSTEMROOT%\\System32\\pcaui.exe" wide //weight: 1
        $x_1_7 = "%SYSTEMROOT%\\pcaui.exe" wide //weight: 1
        $x_1_8 = "%SYSTEMROOT%\\System32\\dvdplay.exe" wide //weight: 1
        $x_1_9 = "%SYSTEMROOT%\\dvdplay.exe" wide //weight: 1
        $x_1_10 = "%SYSTEMROOT%\\System32\\hh.exe" wide //weight: 1
        $x_1_11 = "%SYSTEMROOT%\\hh.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

