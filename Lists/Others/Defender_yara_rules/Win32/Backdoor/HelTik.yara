rule Backdoor_Win32_HelTik_A_2147695054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/HelTik.A"
        threat_id = "2147695054"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "HelTik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 6c 6f 62 61 6c 5c 50 6e 50 5f 4e 6f 5f 4d 61 6e 61 67 65 6d 65 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 6f 74 20 53 75 70 70 6f 72 74 20 54 68 69 73 20 46 75 6e 63 74 69 6f 6e 21 00}  //weight: 1, accuracy: High
        $x_2_3 = {c6 85 fd fe ff ff 4d c6 85 fe fe ff ff 49 c6 85 ff fe ff ff 43 c6 85 00 ff ff ff 52 c6 85 01 ff ff ff 30 c6 85 02 ff ff ff 53 c6 85 03 ff ff ff 30 c6 85 04 ff ff ff 46 c6 85 05 ff ff ff 54}  //weight: 2, accuracy: High
        $x_2_4 = {c6 85 fc fe ff ff 43 c6 85 fd fe ff ff 30 c6 85 fe fe ff ff 52 c6 85 ff fe ff ff 50 c6 85 00 ff ff ff 30 c6 85 01 ff ff ff 52 c6 85 02 ff ff ff 41 c6 85 03 ff ff ff 54 c6 85 04 ff ff ff 49 c6 85 05 ff ff ff 30 c6 85 06 ff ff ff 4e}  //weight: 2, accuracy: High
        $x_1_5 = {49 49 53 43 4d 44 20 45 72 72 6f 72 3a 25 64 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

