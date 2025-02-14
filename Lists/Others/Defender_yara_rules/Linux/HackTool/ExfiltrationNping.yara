rule HackTool_Linux_ExfiltrationNping_Z_2147933475_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ExfiltrationNping.Z"
        threat_id = "2147933475"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ExfiltrationNping"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nping" wide //weight: 10
        $x_10_2 = " -c " wide //weight: 10
        $x_10_3 = "--data " wide //weight: 10
        $x_10_4 = " --data-string " wide //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

