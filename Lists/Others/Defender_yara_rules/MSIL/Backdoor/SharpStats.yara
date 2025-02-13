rule Backdoor_MSIL_SharpStats_A_2147740719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SharpStats.A"
        threat_id = "2147740719"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpStats"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "UHIRER874893UIUOFUGHEWROUIRGH35" wide //weight: 10
        $x_10_2 = "temp_gh_12.dat" wide //weight: 10
        $x_10_3 = "\\GoogleUpdate\\obj\\Release\\GoogleUpdate.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

