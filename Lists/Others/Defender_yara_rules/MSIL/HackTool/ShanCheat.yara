rule HackTool_MSIL_ShanCheat_GVA_2147942229_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/ShanCheat.GVA!MTB"
        threat_id = "2147942229"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ShanCheat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://cdn.glitch.global/8290189a-044c-494d-9957-5b2e993ca180/rqago1.dll?v=1726322804507" wide //weight: 2
        $x_1_2 = "FUCK WITH YOUR MOM THIS FOR FREE PANEL WHY CRACK:" wide //weight: 1
        $x_1_3 = "credentials.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

