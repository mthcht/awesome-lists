rule Trojan_Win32_Nuktob_A_2147690392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nuktob.A"
        threat_id = "2147690392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuktob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 55 70 64 61 74 65 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 4f 53 53 59 53 56 43 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {6c 6f 67 2e 74 78 74 00 4f 53 53 59 53 56 43 2e 65 78 65 00 63 6f 6e 66 69 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_3_4 = {6b 75 6e 64 65 6e 70 66 6c 65 67 65 2e 6d 65 6e 72 61 64 2e 64 65 00}  //weight: 3, accuracy: High
        $x_1_5 = {8b d6 66 89 07 8b c3 2b d3 8d 49 00 8a 08 88 0c 02 40 84 c9 75 f6 8d 46 ff 8d 49 00 8a 48 01 40 84 c9 75 f8 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

