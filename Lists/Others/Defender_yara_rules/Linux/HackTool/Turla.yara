rule HackTool_Linux_Turla_HA_2147843612_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Turla.HA"
        threat_id = "2147843612"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Turla"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tar" wide //weight: 1
        $x_1_2 = "eee.tar" wide //weight: 1
        $x_1_3 = "dt25" wide //weight: 1
        $x_1_4 = "ufsr" wide //weight: 1
        $x_1_5 = "sc ux" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

