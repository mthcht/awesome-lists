rule HackTool_Linux_SuspCommandExecution_A_2147946559_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SuspCommandExecution.A"
        threat_id = "2147946559"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SuspCommandExecution"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "sudo -S -p" wide //weight: 5
        $x_5_2 = "password:" wide //weight: 5
        $x_5_3 = "bash -c 'base64 -d <<< " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

