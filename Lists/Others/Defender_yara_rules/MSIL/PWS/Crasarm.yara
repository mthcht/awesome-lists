rule PWS_MSIL_Crasarm_A_2147688831_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Crasarm.A"
        threat_id = "2147688831"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crasarm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 4d 53 4e 37 35 50 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "SmartStealer Cracked" ascii //weight: 1
        $x_1_3 = "password_value" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

