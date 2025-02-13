rule HackTool_MSIL_CiFlooder_A_2147705591_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/CiFlooder.A"
        threat_id = "2147705591"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CiFlooder"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[ HTTP Flooder ]" wide //weight: 1
        $x_1_2 = "[URL/IP]" wide //weight: 1
        $x_1_3 = "flooder.pdb" ascii //weight: 1
        $x_1_4 = "Content-length: 5235" wide //weight: 1
        $x_1_5 = "Cloner1960" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

