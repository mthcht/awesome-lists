rule Backdoor_Win32_Chafesi_A_2147619188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Chafesi.A"
        threat_id = "2147619188"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Chafesi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 61 63 61 72 69 70 73 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 00 55 00 73 00 65 00 72 00 20 00 41 00 67 00 65 00 6e 00 74 00 5c 00 50 00 6f 00 73 00 74 00 20 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 5c 00 61 00 62 00 63 00 3a 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {3a 00 63 00 62 00 61 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {67 72 61 62 61 72 61 72 63 68 69 76 6f 00}  //weight: 1, accuracy: High
        $x_1_5 = {6a 68 52 ff d6 8d 85 ?? ?? ff ff 6a 6f 50 ff d6 8d 8d ?? ?? ff ff 6a 73 51 ff d6 8d 95 ?? ?? ff ff 6a 74 52 ff d6 8d 85 ?? ?? ff ff 6a 73}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 38 50 ff d6 8d 8d ?? ?? ff ff 6a 39 51 ff d6 8d 95 ?? ?? ff ff 6a 2b 52 ff d6 8d 85 ?? ?? ff ff 6a 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

