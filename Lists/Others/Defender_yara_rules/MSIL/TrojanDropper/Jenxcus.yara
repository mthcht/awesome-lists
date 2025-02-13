rule TrojanDropper_MSIL_Jenxcus_B_2147684569_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Jenxcus.B"
        threat_id = "2147684569"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jenxcus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "('<[ coded bY njq8 ]>'" ascii //weight: 1
        $x_1_2 = "VBS|*.Vbs" wide //weight: 1
        $x_1_3 = "Building Worm Nj" ascii //weight: 1
        $x_1_4 = "nj_worm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

