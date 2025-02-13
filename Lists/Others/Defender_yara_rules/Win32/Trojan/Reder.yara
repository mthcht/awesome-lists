rule Trojan_Win32_Reder_A_2147648921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reder.A"
        threat_id = "2147648921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {7e 0e 8a 04 32 88 04 31 83 c2 03 41 3b d7 7c f2}  //weight: 6, accuracy: High
        $x_1_2 = "yheujxbveop" ascii //weight: 1
        $x_1_3 = {69 6e 69 2e 73 65 6c 69 66 6f 72 70 00}  //weight: 1, accuracy: High
        $x_1_4 = "cdamfrdtg" ascii //weight: 1
        $x_1_5 = {55 73 64 44 70 70 50 66 52 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 7a 7a 41 76 66 53 62 67 53 74 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {65 6a 6f 65 6a 6f 6e 73 78 21 33 32 00}  //weight: 1, accuracy: High
        $x_1_8 = {21 72 65 64 65 72 21 00}  //weight: 1, accuracy: High
        $x_1_9 = {21 63 6f 6e 74 65 6e 74 21 00}  //weight: 1, accuracy: High
        $x_1_10 = {21 73 74 6f 72 61 67 65 21 00}  //weight: 1, accuracy: High
        $x_1_11 = {21 6b 69 6c 6c 21 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((9 of ($x_1_*))) or
            ((1 of ($x_6_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

