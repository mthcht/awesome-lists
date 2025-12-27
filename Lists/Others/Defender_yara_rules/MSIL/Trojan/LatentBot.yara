rule Trojan_MSIL_LatentBot_ALB_2147957688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LatentBot.ALB!MTB"
        threat_id = "2147957688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LatentBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 17 59 13 08 11 08 16 31 64 0e 05 2c 1e 0e 05 8e 69 17 31 17 0e 05 8e 69 09 6f ?? 00 00 0a 18 5a 58 19 5d 2d 06 16 28 ?? 00 00 0a 06 12 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

