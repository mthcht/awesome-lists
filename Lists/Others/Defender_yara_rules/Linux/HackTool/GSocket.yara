rule HackTool_Linux_GSocket_A_2147967888_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/GSocket.A"
        threat_id = "2147967888"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "GSocket"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "curl " wide //weight: 4
        $x_4_2 = "wget " wide //weight: 4
        $x_6_3 = "gsocket.io/x" wide //weight: 6
        $x_6_4 = "gsocket.io/y" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_4_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

