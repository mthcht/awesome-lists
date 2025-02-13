rule Trojan_Win32_Cudofows_A_2147687636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cudofows.A"
        threat_id = "2147687636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cudofows"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c6 83 c0 fb 88 46 01 8b c8 8b d0 c1 e8 10 c1 e9 18 88 46 03 c1 ea 08 8d 44 24 08 50 88 4e 04 c6 06 e9 88 56 02}  //weight: 2, accuracy: High
        $x_1_2 = {6a 28 8d 94 24 60 01 00 00 52 56 ff 15 ?? ?? ?? ?? 68 03 01 00 00 8d 44 24 55 56 50 c6 44 24 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 23 8d 84 24 5c 01 00 00 50 6a 00 ff ?? ?? ?? ?? ?? 68 03 01 00 00 8d 4c 24 55 6a 00 51 c6 44 24 5c 00 e8}  //weight: 1, accuracy: Low
        $x_2_4 = {0f b6 14 32 32 14 2f 47 83 6c 24 14 01 88 57 ff 75 a3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

