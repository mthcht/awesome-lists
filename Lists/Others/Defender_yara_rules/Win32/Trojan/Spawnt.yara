rule Trojan_Win32_Spawnt_B_2147634188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spawnt.B"
        threat_id = "2147634188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spawnt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":\\Test" ascii //weight: 1
        $x_1_2 = "OlxUZXN0" ascii //weight: 1
        $x_4_3 = ":Flinched" ascii //weight: 4
        $x_4_4 = "OkZsaW5jaGVk" ascii //weight: 4
        $x_6_5 = {6c 64 72 2e 65 78 65 02 00 6e 16 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32}  //weight: 6, accuracy: Low
        $x_5_6 = {6b c0 28 5d 01 c5 03 5d 0c 53 8d 6c 24 20 ff 75 00 (ff 15 ?? ?? ?? ??|e8 ?? ?? ?? ??) ff 84 24 ?? ?? ?? ?? ?? ?? 68 00 00 00 00 68 04 00 00 00}  //weight: 5, accuracy: Low
        $x_5_7 = {81 fb 02 c4 97 70 75 3b e8 ?? ?? ?? ?? 50 50}  //weight: 5, accuracy: Low
        $x_10_8 = {83 fb 02 7c 1d 8b 1d ?? ?? ?? ?? 83 fb 06 7f 12 8b 1d ?? ?? ?? ?? 83 fb 05 74 07 b8 01 00 00 00 eb 02 31 c0 21 c0 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_5_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((1 of ($x_10_*) and 1 of ($x_6_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

