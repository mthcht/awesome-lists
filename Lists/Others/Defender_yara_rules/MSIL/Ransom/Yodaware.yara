rule Ransom_MSIL_Yodaware_C_2147788290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Yodaware.C"
        threat_id = "2147788290"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yodaware"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PxRxOxCxMxOxNx" wide //weight: 1
        $x_1_2 = "Fusion Log:" wide //weight: 1
        $x_1_3 = "helloworld.pr.txt" ascii //weight: 1
        $x_1_4 = "\\$SysReset\\Logs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_Yodaware_C_2147788290_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Yodaware.C"
        threat_id = "2147788290"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Yodaware"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your files are encrypted!!!" wide //weight: 1
        $x_1_2 = ".lock" wide //weight: 1
        $x_1_3 = "__READ__ME__.txt" wide //weight: 1
        $x_1_4 = {53 00 65 00 6e 00 64 00 20 00 24 00 [0-16] 20 00 77 00 6f 00 72 00 74 00 68 00 20 00 6f 00 66 00 20 00 4d 00 6f 00 6e 00 65 00 72 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

