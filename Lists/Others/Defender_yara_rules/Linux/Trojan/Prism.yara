rule Trojan_Linux_Prism_B_2147816690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Prism.B!MTB"
        threat_id = "2147816690"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Prism"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 48 98 48 c1 e0 03 48 03 45 d0 48 8b 00 48 89 c7 e8 ?? ?? ?? ?? 48 89 c2 8b 45 ec 48 98 48 c1 e0 03 48 03 45 d0 48 8b 00 be 20 00 00 00 48 89 c7 e8 ?? ?? ?? ?? 83 45 ec 01 8b 45 ec 3b 45 dc 7c bc e8 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {bf 00 00 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

