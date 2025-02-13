rule TrojanSpy_MSIL_Mijrun_A_2147706575_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Mijrun.A"
        threat_id = "2147706575"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mijrun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 52 75 6e 00 4b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = "@gmail.com" wide //weight: 1
        $x_1_3 = "Screenshot from" wide //weight: 1
        $x_1_4 = "Keys log from:" wide //weight: 1
        $x_1_5 = "\\Microsoft\\Windows IMJ" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

