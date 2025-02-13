rule Worm_Win32_Yacspeel_A_2147618451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yacspeel.gen!A"
        threat_id = "2147618451"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yacspeel"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 b1 8b 44 24 14 50 ff 15 14 00 01 10 b9 ?? 5b 01 10 e8 ?? ?? 00 00 68 00 5c 26 05 ff 15 ?? ?? 01 10 8b 0d ?? 5b 01 10 6a 01 81 c1 20 07 00 00 6a 04 51 b9}  //weight: 10, accuracy: Low
        $x_10_2 = {74 24 8d 54 24 10 52 e8 ef 31 00 00 83 c4 04 e8 ?? cd ff ff 8b 46 0c 8b 4c 24 10 89 48 10 8b 4e 0c e8 73 01 00 00 68 00 5c 26 05 ff d7 8b 15 ?? 5b 01 10 8b 82 44 08 00 00 85 c0 75 2f 8b ce e8 25 09 00 00 85 c0 74 24}  //weight: 10, accuracy: Low
        $x_10_3 = "microsoft visual c++ runtime library" ascii //weight: 10
        $x_1_4 = "shell\\open\\Command=rundll32.exe .\\desktop.dll,InstallM" ascii //weight: 1
        $x_1_5 = "timout" ascii //weight: 1
        $x_1_6 = "SleepingDaysCnt" ascii //weight: 1
        $x_1_7 = "{1AEFA55F-60A6-4817-B2D5-12E2E48617F4}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

