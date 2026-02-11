rule HackTool_MSIL_Keygen_C_2147962846_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Keygen.C!AMTB"
        threat_id = "2147962846"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Keygen"
        severity = "High"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keygen for CoolwareMax WebcamMax" ascii //weight: 1
        $x_1_2 = "[Your code here..]" ascii //weight: 1
        $x_1_3 = "&Generate" ascii //weight: 1
        $x_1_4 = ".:AMPED:." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

