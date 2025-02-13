rule Trojan_MSIL_Cryptbot_ACO_2147932340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptbot.ACO!MTB"
        threat_id = "2147932340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 0d 2b 2a 08 09 06 09 91 09 1f 3b 5a 20 00 01 00 00 5d d2 61 d2 9c 08 09 8f ?? 00 00 01 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d 09 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

