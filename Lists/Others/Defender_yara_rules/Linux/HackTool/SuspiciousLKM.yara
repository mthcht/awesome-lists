rule HackTool_Linux_SuspiciousLKM_A_2147960299_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspiciousLKM.A"
        threat_id = "2147960299"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspiciousLKM"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "Mandiant Kernel Module loaded" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

