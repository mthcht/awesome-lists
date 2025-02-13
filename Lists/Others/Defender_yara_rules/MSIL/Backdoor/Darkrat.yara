rule Backdoor_MSIL_Darkrat_YA_2147733453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Darkrat.YA!MTB"
        threat_id = "2147733453"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "darkratfud" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "&os=" wide //weight: 1
        $x_1_4 = "&pc=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

