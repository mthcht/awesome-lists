rule Trojan_Linux_Whirpool_A_2147849234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Whirpool.A!MTB"
        threat_id = "2147849234"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Whirpool"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 20 32 3e 26 66 c7 40 04 31 00}  //weight: 1, accuracy: High
        $x_1_2 = "SSLShell.c" ascii //weight: 1
        $x_1_3 = "plain_connect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

