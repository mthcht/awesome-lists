rule DoS_Linux_WprBlightre_A_2147894305_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Linux/WprBlightre.A"
        threat_id = "2147894305"
        type = "DoS"
        platform = "Linux: Linux platform"
        family = "WprBlightre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "send attempt while closed" ascii //weight: 1
        $x_1_2 = "[!] Waiting For Queue" ascii //weight: 1
        $x_1_3 = {2e 00 00 00 42 00 00 00 69 00 00 00 42 00 00 00 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

