rule Trojan_Linux_KrustyLoader_A_2147943672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/KrustyLoader.A!MTB"
        threat_id = "2147943672"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "KrustyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 54 fb 40 48 c1 c2 24 4c 21 d2 48 33 14 fb 48 89 d6 49 89 d0 49 c1 e0 0c 4d 21 e0 49 31 d0 48 c1 e2 04 4c 21 ea 48 c1 e6 08 4c 21 f6 48 31 d6 49 31 f0 4c 89 44 fb 40}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 84 d4 c0 04 00 00 48 89 c1 48 c1 e9 08 48 31 c1 4c 21 e1 48 31 c8 48 c1 e1 08 48 31 c1 48 89 c8 48 c1 e8 04 48 31 c8 4c 21 f8 48 31 c1 48 c1 e0 04 48 31 c8 48 89 84 d4 c0 04 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

