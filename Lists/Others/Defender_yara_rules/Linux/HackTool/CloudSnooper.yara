rule HackTool_Linux_CloudSnooper_D_2147773332_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/CloudSnooper.D"
        threat_id = "2147773332"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "CloudSnooper"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rrtserver -d" wide //weight: 5
        $x_5_2 = "rrtserver -s " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

