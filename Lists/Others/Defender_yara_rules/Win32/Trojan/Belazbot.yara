rule Trojan_Win32_Belazbot_A_2147710264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Belazbot.A!bit"
        threat_id = "2147710264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Belazbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 8b 45 f0 01 c2 8b 4d f4 8b 45 08 01 c8 8a 00 83 f0 02 88 02 ff 45 f4}  //weight: 1, accuracy: High
        $x_2_2 = {89 45 d4 c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00 89 45 d0 c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00 89 45 cc c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00 89 45 c8 c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00 89 45 c4 c7 04 24 ?? ?? 40 00 e8 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 0d 0a 48 6f 73 74 3a 20 25 73 0d 0a 0d 0a 00 72 62 00 77 62 2b 00 0d 0a 0d 0a 00 4d 5a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

