rule Trojan_Win32_Fasong_2147807962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fasong.dwuq!MTB"
        threat_id = "2147807962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fasong"
        severity = "Critical"
        info = "dwuq: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 17 89 d0 33 d2 89 17 8b e8 ff d5 83 3f 00 75 ef}  //weight: 10, accuracy: High
        $x_1_2 = "kav9x.exe" ascii //weight: 1
        $x_1_3 = "ravmon.exe" ascii //weight: 1
        $x_1_4 = "watcher.exe" ascii //weight: 1
        $x_1_5 = "passwordguard.exe" ascii //weight: 1
        $x_1_6 = "autorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

