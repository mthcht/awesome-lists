rule Backdoor_Linux_Ldaxm_SC2_2147966269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Ldaxm.SC2"
        threat_id = "2147966269"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Ldaxm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl " wide //weight: 10
        $x_10_2 = "-o /tmp/" wide //weight: 10
        $x_10_3 = "nohup python3 /tmp/" wide //weight: 10
        $x_10_4 = "/dev/null" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

