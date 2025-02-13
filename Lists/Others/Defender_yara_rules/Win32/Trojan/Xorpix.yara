rule Trojan_Win32_Xorpix_C_2147595046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xorpix.C"
        threat_id = "2147595046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xorpix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d 08 87 ff 8b 75 10 8b df 03 5d 0c 8a 06 eb [0-6] 30 07 [0-6] 47 46}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 00 41 73 79 6e 63 68 72 6f 6e 6f 75 73 00 90 90 49 6d 70 65 72 73 6f 6e 61 74 65 00 90 77 73}  //weight: 1, accuracy: High
        $x_1_3 = {90 61 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 00 90 53 74 61 72 74 75 70 00 90 90 53 68 61 72 65 64}  //weight: 1, accuracy: High
        $x_1_4 = {e8 00 00 00 00 58 05 0c 00 00 00 50 e9}  //weight: 1, accuracy: High
        $x_1_5 = {90 61 44 6c 6c 4e 61 6d 65 00 60 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

