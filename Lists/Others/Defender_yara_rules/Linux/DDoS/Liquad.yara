rule DDoS_Linux_Liquad_A_2147812156_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Liquad.A!MTB"
        threat_id = "2147812156"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Liquad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 ba 04 00 00 00 00 00 00 00 b9 00 40 00 00 b8 00 00 00 00 48 bf 00 08 00 00 00 00 00 00 4c 8d 85 ?? ?? ff ff 48 89 bd ?? ?? ff ff 4c 89 c7 48 89 b5 ?? ?? ff ff 89 c6 4c 8b 85 ?? ?? ff ff 48 89 95 ?? ?? ff ff 4c 89 c2 89 8d ?? ?? ff ff e8 ?? ?? ff ff 8b 7d ?? 48 8b b5 ?? ?? ff ff 48 8b 95 ?? ?? ff ff 8b 8d ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_1_2 = "%c]0;Bots connected: %d | Clients connected: %d%c" ascii //weight: 1
        $x_1_3 = "LOLNOGTFO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

