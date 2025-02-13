rule TrojanClicker_MSIL_Broclik_A_2147711632_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Broclik.A"
        threat_id = "2147711632"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Broclik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://black" wide //weight: 1
        $x_1_2 = "(((f|XX){1}XX)" wide //weight: 1
        $x_1_3 = "#XXXX0:" wide //weight: 1
        $x_1_4 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-32] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {63 00 6c 00 69 00 63 00 6b 00 32 00 ?? ?? 63 00 6c 00 69 00 63 00 6b 00 33 00 ?? ?? 63 00 6c 00 69 00 63 00 6b 00 34 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_MSIL_Broclik_B_2147721718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Broclik.B!bit"
        threat_id = "2147721718"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Broclik"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5f 00 [0-16] 61 00 6c 00 6c 00 75 00 73 00 65 00 72 00 73 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "fyjFRRRRR" wide //weight: 1
        $x_1_4 = {58 00 58 00 58 00 58 00 30 00 3a 00 [0-16] 58 00 58 00 58 00 58 00 31 00 3a 00 [0-16] 58 00 58 00 58 00 58 00 32 00 3a 00 [0-16] 58 00 58 00 58 00 58 00 33 00 3a 00 [0-16] 58 00 58 00 58 00 58 00 34 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_5 = "(((f|XX){1}XX)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

