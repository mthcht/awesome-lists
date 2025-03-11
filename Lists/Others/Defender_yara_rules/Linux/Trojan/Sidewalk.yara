rule Trojan_Linux_Sidewalk_D_2147935672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sidewalk.D!MTB"
        threat_id = "2147935672"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sidewalk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 bb 48 f6 09 00 00 75 ?? 68 ff 00 00 00 8d ?? ?? ?? ?? ?? ?? 56 e8 d8 03 00 00 c6 84 24 ab 01 00 00 00 5d 5a 85 c0 75 ?? 6a 2e 56 e8 38 55 ff ff 5e 5f 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {53 57 ff 74 24 64 e8 a8 52 ff ff 8b 44 24 68 01 d8 8b 54 24 6c 29 da 89 c3 f7 db 83 e3 03 29 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

