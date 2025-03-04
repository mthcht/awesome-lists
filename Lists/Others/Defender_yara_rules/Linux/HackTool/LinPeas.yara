rule HackTool_Linux_LinPEAS_A_2147916734_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/LinPEAS.A"
        threat_id = "2147916734"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "LinPEAS"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl" wide //weight: 1
        $x_1_2 = "wget" wide //weight: 1
        $x_10_3 = "http://linpeas.sh" wide //weight: 10
        $x_10_4 = "https://linpeas.sh" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

