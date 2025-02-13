rule DDoS_Linux_WprBlightre_A_2147894699_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/WprBlightre.A!MTB"
        threat_id = "2147894699"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "WprBlightre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 00 00 42 00 00 00 69 00 00 00 42 00 00 00 69 00 00 00 00 00 00 00 2e 00 00 00 6f 00 00 00 75 00 00 00 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 21 5d 20 57 61 69 74 69 6e 67 20 46 6f 72 20 51 75 65 75 65 20 00 5b 2b 5d 20 52 6f 75 6e 64 20 25 64 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

