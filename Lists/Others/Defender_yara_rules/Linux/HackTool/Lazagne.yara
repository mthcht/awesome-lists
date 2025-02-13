rule HackTool_Linux_Lazagne_K_2147891676_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Lazagne.K!MTB"
        threat_id = "2147891676"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Lazagne"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lazagne.config" ascii //weight: 1
        $x_1_2 = "lazagne.softwares" ascii //weight: 1
        $x_1_3 = "slaZagne" ascii //weight: 1
        $x_1_4 = "Cannot side-load external archive %s (code %d)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

