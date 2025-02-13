rule TrojanClicker_MSIL_Lnkhit_B_2147642115_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Lnkhit.B"
        threat_id = "2147642115"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lnkhit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 00 76 00 61 00 73 00 74 00 25 00 32 00 30 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {77 69 6e 64 6f 77 73 5f 37 5f 77 61 6c 6c 70 61 70 65 72 5f 62 79 5f 70 5f 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {28 41 76 61 73 74 29 20 50 72 6f 20 2d 5b 4b 65 79 47 65 6e 5d 2d 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-17] 2e 00 6c 00 69 00 6e 00 6b 00 62 00 75 00 63 00 6b 00 73 00 2e 00 63 00 6f 00 6d 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_MSIL_Lnkhit_C_2147647647_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Lnkhit.C"
        threat_id = "2147647647"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lnkhit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svcupdate." wide //weight: 1
        $x_1_2 = "\\svchost.exe" wide //weight: 1
        $x_1_3 = "/in.php" wide //weight: 1
        $x_1_4 = "clicks left" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

