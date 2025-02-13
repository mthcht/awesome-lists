rule TrojanProxy_MSIL_Segyroxb_A_2147706907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:MSIL/Segyroxb.A"
        threat_id = "2147706907"
        type = "TrojanProxy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Segyroxb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "/officialsegway.com/xx.dat" wide //weight: 8
        $x_4_2 = "/adventureonlinegames.org/ph/notify.php" wide //weight: 4
        $x_2_3 = "\\Users\\eCoLoGy\\Documents" ascii //weight: 2
        $x_2_4 = "Projects\\MyPh\\MyPh\\obj\\Debug\\MyPh.pdb" ascii //weight: 2
        $x_1_5 = {4b 69 6c 6c 00 43 6f 6e 74 72 6f 6c 00 53 79 73 74 65 6d 00 46 6f 72 6d 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 61 74 61 72 6e 61 76 00 4d 79 50 68 2e 4d 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

