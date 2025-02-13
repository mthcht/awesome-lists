rule HackTool_Linux_Spectre_A_2147927962_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Spectre.A"
        threat_id = "2147927962"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Spectre"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "======= Memory map: ========" ascii //weight: 1
        $x_1_2 = "======= Backtrace: =========" ascii //weight: 1
        $x_1_3 = "TEST TEST TEST" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

