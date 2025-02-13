rule Backdoor_Win32_Leenstic_A_2147688068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Leenstic.A"
        threat_id = "2147688068"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Leenstic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0a 32 88 ?? ?? ?? ?? 8b 55 08 03 55 fc 88 0a eb ?? 8b 45 08 03 45 fc 0f be 08 f7 d1 8b 55 08 03 55 fc 88 0a eb}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 02 8d 55 f8 52 6a 23 ff 55 fc ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6a 00 6a 04 8d 55 f0 52 6a 07 8b 45 08 50 ff 55 ec}  //weight: 1, accuracy: Low
        $x_1_3 = {57 69 72 65 73 68 61 72 6b 00 00 00 74 63 70 76 69 65 77 00 4d 53 41 53 43 75 69 00 6d 73 6d 70 65 6e 67}  //weight: 1, accuracy: High
        $x_1_4 = {73 61 6e 64 62 6f 78 00 68 6f 6e 65 79 00 00 00 76 6d 77 61 72 65 00 00 63 75 72 72 65 6e 74 75 73 65 72}  //weight: 1, accuracy: High
        $x_1_5 = "%s=%s&%s=%s&%s=%i&%s=%s&%s=%i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

