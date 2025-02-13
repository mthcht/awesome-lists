rule Trojan_Linux_Diamorphine_A_2147819196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Diamorphine.A!MTB"
        threat_id = "2147819196"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Diamorphine"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hacked_kill" ascii //weight: 1
        $x_1_2 = "diamorphine_cleanup" ascii //weight: 1
        $x_1_3 = "hacked_getdents" ascii //weight: 1
        $x_1_4 = "m0nad" ascii //weight: 1
        $x_1_5 = "LKM rootkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

