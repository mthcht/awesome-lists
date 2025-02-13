rule Trojan_Win32_Bojotuc_A_2147632741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bojotuc.A"
        threat_id = "2147632741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bojotuc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4c 24 14 8b 51 24 03 54 24 10 8b 49 1c 0f b7 14 3a 8d 14 91 8b 0c 3a 03 cf 89 08 83 7c 24 0c 03 75}  //weight: 2, accuracy: High
        $x_2_2 = {8a 10 80 f2 ?? 88 11 83 c0 02 41 66 83 38 00 75 ef}  //weight: 2, accuracy: Low
        $x_1_3 = {8b 5c 24 08 91 80 07 00 53 b0 ?? b1 ?? b2}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 7c 24 08 07 00 57 b0 ?? b1 ?? b2}  //weight: 1, accuracy: Low
        $x_1_5 = {53 56 57 b0 ?? b1 ?? b2 ?? 8b 7c 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

