rule Ransom_MSIL_RmamoCoder_SK_2147753022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/RmamoCoder.SK!MTB"
        threat_id = "2147753022"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RmamoCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\_RMAMO\\_RMAMO\\obj\\Debug\\_RMAMO.pdb" ascii //weight: 1
        $x_1_2 = ".Encrypted" wide //weight: 1
        $x_1_3 = "\\Passz.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

