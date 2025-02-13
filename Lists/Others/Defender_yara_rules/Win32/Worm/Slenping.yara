rule Worm_Win32_Slenping_B_2147608412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Slenping.gen!B"
        threat_id = "2147608412"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenping"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tSkMainForm.UnicodeClass" ascii //weight: 1
        $x_1_2 = "PuTTY" ascii //weight: 1
        $x_1_3 = "TFrmMain" ascii //weight: 1
        $x_1_4 = "YahooBuddyMain" ascii //weight: 1
        $x_1_5 = "MSBLWindowClass" ascii //weight: 1
        $x_1_6 = "_Oscar_StatusNotify" ascii //weight: 1
        $x_1_7 = "__oxFrame.class__" ascii //weight: 1
        $x_1_8 = "%s\\removeMe%i%i%i%i.bat" ascii //weight: 1
        $x_1_9 = "ping 0.0.0.0>nul" ascii //weight: 1
        $x_1_10 = "netsh firewall set allowedprogram \"%s\" ENABLE" ascii //weight: 1
        $x_5_11 = {6d 47 fe 74 e8 bf c2 45 90 35 d1 5e 33 0a 24 6d}  //weight: 5, accuracy: High
        $x_10_12 = {55 6a 01 55 6a 11 ff d6 55 55 55 6a 56 ff d3 50 ff d6 55 6a 03 6a 2d 6a 11 ff d6}  //weight: 10, accuracy: High
        $x_10_13 = {56 6a 01 56 6a 11 ff d3 56 56 56 6a 56 ?? ?? ?? ?? ?? ?? 50 ff d3 56 6a 03 6a 2d 6a 11 ff d3}  //weight: 10, accuracy: Low
        $x_15_14 = {3d 46 27 00 00 74 ?? 03 f0 83 fe 0c 7d ?? 6a 00 b9 0c 00 00 00 2b ce 51 8d 54 34 ?? 52 55 ff d7}  //weight: 15, accuracy: Low
        $x_15_15 = {3d 46 27 00 00 74 ?? 03 f8 3b 7d ?? 7d ?? 8b 45 0c 6a 00 2b c7 50 8d 04 1f 50 ff 75 ?? ff d6}  //weight: 15, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_15_*))) or
            (all of ($x*))
        )
}

