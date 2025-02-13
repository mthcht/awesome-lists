rule Trojan_Win32_ChkBot_A_2147696159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ChkBot.A"
        threat_id = "2147696159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ChkBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 65 f8 ff 15 ?? ?? ?? ?? 90 90 90 90 39 65 f8 74 0d 68 06 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 68 74 74 70 3a 2f 2f [0-32] 2f 63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d 00 47 45 54 00 68 74 74 70 3a 2f 2f [0-37] 2e 74 78 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 6d 63 3d 47 65 74 4f 62 6a 65 63 74 28 22 57 69 6e 6d 67 6d 74 73 3a 22 29 2e 49 6e 73 74 61 6e 63 65 73 4f 66 28 22 57 69 6e 33 32 5f 4e 65 74 77 6f 72 6b 41 64 61 70 74 65 72 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 22 29 0d 0a 20 20 20 20 46 6f 72 20 45 61 63 68 20 6d 6f 20 49 6e 20 6d 63 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {00 26 76 65 72 3d 03 00 2e 03 00 00 26 6f 73 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

