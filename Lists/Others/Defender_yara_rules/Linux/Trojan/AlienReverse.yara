rule Trojan_Linux_AlienReverse_A_2147844754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/AlienReverse.A!MTB"
        threat_id = "2147844754"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "AlienReverse"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/AlienReverse" ascii //weight: 1
        $x_1_2 = "--reverse-address=" ascii //weight: 1
        $x_1_3 = "13CShellManager" ascii //weight: 1
        $x_1_4 = "SysReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

