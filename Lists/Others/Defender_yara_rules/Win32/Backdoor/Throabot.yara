rule Backdoor_Win32_Throabot_A_2147607321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Throabot.gen!A"
        threat_id = "2147607321"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Throabot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 18 00 00 00 8b 40 30 0f b6 40 02 85 c0 75 02 eb 04 c6 45 ff 01 58 80 7d ff 00 75 0a 6a 0a ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {7e 10 80 34 3e c9 57 46 e8 ?? ?? 00 00 3b f0 59 7c f0}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 14 3d 80 7d 05 00 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = {74 26 56 0f be c9 c1 e0 04 03 c1 8b c8 42 81 e1 00 00 00 f0 74 07 8b f1 c1 ee 18 33 c6 f7 d1 23 c1 8a 0a 84 c9 75 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

