rule Trojan_MSIL_lummac_NIT_2147934879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/lummac.NIT!MTB"
        threat_id = "2147934879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 07 1f 28 5a 58 13 08 28 ?? 00 00 0a 07 11 08 1e 6f ?? 00 00 0a 17 8d 20 00 00 01 6f ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 2c 3e 07 11 08 1f 14 58 28 ?? 00 00 0a 13 0a 07 11 08 1f 10 58 28 ?? 00 00 0a 13 0b 11 0b 8d 15 00 00 01 80 04 00 00 04 07 11 0a 6e 7e 04 00 00 04 16 6a 11 0b 6e 28 ?? 00 00 0a 17 13 06 de 31 de 21 25 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 25 2d 06 26 72 27 00 00 70 28 ?? 00 00 0a 26 de 00 11 07 17 58 13 07 11 07 09 3f 4f ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {11 2f 17 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2f 11 30 11 2d 11 2f 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 30 73 18 00 00 0a 13 34 11 34 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 34 16 6f ?? 00 00 0a 9c 11 2d 11 2f 91 11 2d 11 30 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 35 73 18 00 00 0a 13 36 11 36 11 2d 11 35}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

