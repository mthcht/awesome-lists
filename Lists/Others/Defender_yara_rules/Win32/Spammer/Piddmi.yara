rule Spammer_Win32_Piddmi_A_2147602537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Piddmi.gen!A"
        threat_id = "2147602537"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Piddmi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 f0 01 00 00 00 c7 45 f4 01 00 00 00 c6 45 e7 00 8b 45 f8 8b 00 8b 55 f0 0f b6 44 10 ff 83 f8 3a 7d 1c 83 e8 21 72 3c 83 e8 02 74 74 83 e8 03 74 6f 83 c0 f8 83 e8 02}  //weight: 10, accuracy: High
        $x_10_2 = {50 68 00 00 00 10 6a 00 8b 45 fc e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 6a 00 6a 00 6a 00 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff 89 45 f4 83 7d f4 00}  //weight: 10, accuracy: Low
        $x_10_3 = {eb 0a 68 60 ea 00 00 e8 ?? ?? ff ff b8 ?? ?? ?? ?? e8 ?? ?? ff ff 8b d8 e8 ?? ?? ff ff 3b d8 0f 84 ?? ?? ff ff e8 ?? ?? ff ff 68 c0 27 09 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 33 c0}  //weight: 10, accuracy: Low
        $x_2_4 = {3b 0d 0a 20 43 68 61 72 73 65 74 3d 57 69 6e 64 6f 77 73 2d 31 32 35 31 00}  //weight: 2, accuracy: High
        $x_2_5 = {4d 49 4d 45 2d 56 65 72 73 69 6f 6e 3a 20 31 2e 30 0d 0a 0d 0a 00}  //weight: 2, accuracy: High
        $x_2_6 = {44 6e 73 51 75 65 72 79 5f 41 00}  //weight: 2, accuracy: High
        $x_2_7 = "mail exchanger" ascii //weight: 2
        $x_2_8 = {6d 6d 2e 70 69 64 00}  //weight: 2, accuracy: High
        $x_2_9 = "[!MULTIPART!]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_2_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

