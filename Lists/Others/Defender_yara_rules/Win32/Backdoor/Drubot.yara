rule Backdoor_Win32_Drubot_A_2147606989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Drubot.gen!A"
        threat_id = "2147606989"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Drubot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 0f 27 00 00 68 e8 03 00 00 e8 ?? ?? ff ff 59 59 50 6a 09 6a 05 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 8a 10 84 d2 74 10 8b c8 32 54 24 08 88 11 8a 51 01 41 84 d2 75 f2 c3}  //weight: 1, accuracy: High
        $x_1_3 = {7d 08 6a 02 58 e9 ?? ?? 00 00 68 bd 01 00 00 66 c7 45 e8 02 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {44 72 75 64 67 65 62 6f 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

