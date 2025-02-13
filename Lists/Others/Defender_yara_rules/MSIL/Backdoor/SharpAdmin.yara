rule Backdoor_MSIL_SharpAdmin_RDA_2147892223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SharpAdmin.RDA!MTB"
        threat_id = "2147892223"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpAdmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 8d 10 00 00 01 25 16 11 06 a2 6f 14 00 00 0a 26 11 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

