rule Trojan_MSIL_Migaut_PA_2147755294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Migaut.PA!MTB"
        threat_id = "2147755294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Migaut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2d 13 72 ?? ?? 00 70 02 72 ?? ?? 00 70 28 ?? ?? 00 0a 0a 2b 11 72 ?? ?? 00 70 02 72 ?? ?? 00 70 28 ?? ?? 00 0a 0a 72 ?? ?? 00 70 06 73 ?? ?? 00 0a 25 17 6f ?? 00 00 0a 25 16 6f ?? ?? 00 0a 25 17 6f ?? ?? 00 0a 28 ?? ?? 00 0a 26 de}  //weight: 1, accuracy: Low
        $x_1_2 = {07 8e 69 8d ?? 00 00 01 0c 7e 02 00 00 04 ?? ?? 00 00 0a 0d 16 13 05 2b 11 08 11 05 07 11 05 91 09 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

