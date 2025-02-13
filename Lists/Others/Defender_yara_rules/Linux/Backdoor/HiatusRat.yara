rule Backdoor_Linux_HiatusRat_A_2147888112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/HiatusRat.A!MTB"
        threat_id = "2147888112"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "HiatusRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tcp_forward" ascii //weight: 1
        $x_1_2 = "executor" ascii //weight: 1
        $x_1_3 = "upload?uuid=" ascii //weight: 1
        $x_1_4 = "forwarder exist" ascii //weight: 1
        $x_1_5 = "/master/Api/active" ascii //weight: 1
        $x_1_6 = "/master/Api/reply" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

