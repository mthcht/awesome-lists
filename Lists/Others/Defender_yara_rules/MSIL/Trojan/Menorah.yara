rule Trojan_MSIL_Menorah_AMN_2147899166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Menorah.AMN!MTB"
        threat_id = "2147899166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Menorah"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 1f 5c 9d 6f ?? 00 00 0a 25 1f 5c 6f ?? 00 00 0a 17 58 6f ?? 00 00 0a 16 18 6f ?? 00 00 0a 0b 06 8e 69 17 31 15 07 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {0d 16 13 04 2b 35 09 08 11 04 8f ?? 00 00 01 1f 58 13 05 12 05 28 ?? 00 00 0a 1f 32 13 05 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 26 11 04 17 58 13 04 11 04 08 8e 69}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 16 0b 2b 1a 06 07 02 07 91 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

