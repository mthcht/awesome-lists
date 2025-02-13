rule Trojan_Win32_Iceroe_A_2147602790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iceroe.gen!A"
        threat_id = "2147602790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iceroe"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {74 2a 53 8d 45 f8 50 6a 02 8d 45 fc 50 56 ff 15 ?? ?? ?? ?? 80 7d fc 4d 88 5d fe 75 08 80 7d fd 5a 75 02 b3 01}  //weight: 8, accuracy: Low
        $x_8_2 = {74 3c 8d 55 fb 8a 02 3c e9 75 3c 8d 55 fb 8b 52 01 8b c2 83 c0 05 03 45 0c 89 45 f0 8d 45 f4 50 6a 05 8d 45 fb}  //weight: 8, accuracy: High
        $x_8_3 = {89 86 8c 00 00 00 8b ce 89 9e 90 00 00 00 e8 ?? ?? 00 00 6a ff 53 8b c6 8b cf e8 ?? ?? ?? ?? 6a 05 68 ?? ?? ?? ?? 8b cf e8 ?? ?? ?? ?? 6a ff 53 8b c6 8b cd e8 ?? ?? ?? ?? 6a 05}  //weight: 8, accuracy: Low
        $x_2_4 = {63 00 6f 00 72 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {63 00 61 00 72 00 72 00 69 00 65 00 72 00 00 00}  //weight: 2, accuracy: High
        $x_2_6 = "u=0x%.8x&a=0x%.8x&v=0x%.8x&t=%s" wide //weight: 2
        $x_2_7 = "http://%s/download?n=%s&%s" wide //weight: 2
        $x_1_8 = {43 6f 72 65 2e 64 6c 6c 00 53 74 61 72 74 00 53 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 00 6f 00 72 00 65 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 45 00 78 00 65 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {43 00 6f 00 72 00 65 00 2e 00 45 00 78 00 65 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {43 00 6f 00 72 00 65 00 2e 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {54 00 72 00 61 00 66 00 55 00 72 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_13 = {43 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 50 00 6c 00 75 00 67 00 69 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_14 = {4b 00 6e 00 6f 00 63 00 6b 00 44 00 61 00 74 00 65 00 54 00 69 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_8_*))) or
            (all of ($x*))
        )
}

