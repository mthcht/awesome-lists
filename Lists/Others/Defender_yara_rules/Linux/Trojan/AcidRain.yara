rule Trojan_Linux_AcidRain_A_2147923813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/AcidRain.A!MTB"
        threat_id = "2147923813"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "AcidRain"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 86 04 02 00 00 89 45 f0 8b 86 00 02 00 00 85 c0 7e 2a bf 01 00 00 00 90 8d b4 26 00 00 00 00 8b 44 be fc 89 fb 89 04 24 e8 03 2b 00 00 31 c0 89 44 be fc 47 39 9e 00 02 00 00 7f e3 89 34 24 e8 ec 2a 00 00 8b 75 f0 85 f6 75 b4}  //weight: 1, accuracy: High
        $x_1_2 = {01 c3 8b 45 c8 05 01 04 00 00 39 d8 7e 19 b8 00 04 00 00 89 44 24 08 89 7c 24 04 89 34 24 e8 65 1a 00 00 85 c0 7f d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

