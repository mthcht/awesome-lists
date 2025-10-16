rule Trojan_MSIL_SorvePotel_GTF_2147955274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SorvePotel.GTF!MTB"
        threat_id = "2147955274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SorvePotel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 e8 03 00 00 28 ?? ?? ?? 0a 07 17 58 0b 07 1f 1e 32 10 28 ?? 00 00 06 2d 07 16 80 ?? 00 00 04 2a 16 0b 7e ?? 00 00 04 2d d6}  //weight: 5, accuracy: Low
        $x_5_2 = {06 0b 07 28 ?? 00 00 06 0c 08 20 ?? ?? ?? ?? 5f 2c 5c 08 17 5f 2c 57 07 28 ?? 00 00 06 2d 4f 07 28 ?? 00 00 06 2d 47 07 28 ?? 00 00 06 0d 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

