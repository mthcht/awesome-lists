rule HackTool_Linux_Ncrack_C_2147799017_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ncrack.C"
        threat_id = "2147799017"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ncrack"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ncrack-services" ascii //weight: 2
        $x_2_2 = "Ncrack done:" ascii //weight: 2
        $x_2_3 = "Ncrack is using %s for security" ascii //weight: 2
        $x_2_4 = "ncrack_probes" ascii //weight: 2
        $x_2_5 = "fyodor@insecure.org so i can guage support" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

