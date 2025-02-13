rule Backdoor_Win32_NinSky_A_2147709034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/NinSky.A"
        threat_id = "2147709034"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "NinSky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_50_1 = {c7 45 f8 cc cc cc cc c7 45 fc cc cc cc cc 8b 45 08 89 45 fc c7 45 f8 00 00 00 00 eb 09 8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 10 7d 19 0f b6 45 0c 8b 4d fc 03 4d f8 0f b6 11 33 d0 8b 45 fc 03 45 f8 88 10 eb d6}  //weight: 50, accuracy: High
        $x_10_2 = "SkypeControlAPIAttach" ascii //weight: 10
        $x_10_3 = "SkypeControlAPIDiscover" ascii //weight: 10
        $x_1_4 = "[Skype] Data Path :" wide //weight: 1
        $x_1_5 = "[SkypeAccess] Skype Exit" wide //weight: 1
        $x_1_6 = "[SkypeMonitor] Initialize" wide //weight: 1
        $x_1_7 = "[SkypeMonitor] Wait Skype Initialize..." wide //weight: 1
        $x_1_8 = "[SkypeAccess] Skype Accessed.." wide //weight: 1
        $x_1_9 = "[SkypeMessage] Logged out." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

