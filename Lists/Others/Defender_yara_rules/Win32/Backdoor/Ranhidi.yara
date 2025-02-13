rule Backdoor_Win32_Ranhidi_A_2147682961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ranhidi.A"
        threat_id = "2147682961"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranhidi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 70 1c ad 8b 78 08 89 7d fc 8b 45 fc}  //weight: 1, accuracy: High
        $x_1_2 = {6a 28 8d 4c 24 10 8b 84 24 f0 00 00 00 03 c6 50 51 e8 ?? ?? ?? ?? 33 ff 8b 44 24 20 85 c0 76 26 8b 9c 24 74 01 00 00 8b 54 24 2c 8d 04 ba 8b 0c 30 03 ce 51}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 04 33 c0 8a 0a 84 c9 74 19 56 8b f0 c1 ee 1b c1 e0 05 0b f0 0f be c1 8a 4a 01 03 c6 42 84 c9 75 e9 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

