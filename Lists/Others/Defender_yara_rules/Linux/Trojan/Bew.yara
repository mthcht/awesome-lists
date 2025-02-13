rule Trojan_Linux_Bew_A_2147891309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Bew.A!MTB"
        threat_id = "2147891309"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Bew"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 59 89 e0 51 8d 74 88 04 56 50 51 89 35 70 e0 04 08 ad 85 c0 75 fb}  //weight: 1, accuracy: High
        $x_1_2 = "tmpd819is13" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

