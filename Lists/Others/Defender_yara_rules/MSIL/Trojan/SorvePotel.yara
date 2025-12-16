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

rule Trojan_MSIL_SorvePotel_GMT_2147956606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SorvePotel.GMT!MTB"
        threat_id = "2147956606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SorvePotel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fe 0c 27 00 fe 0c 18 00 3b 30 00 00 00 fe 0c 08 00 fe 0c 27 00 46 fe 0c 0b 00 61 52 fe 0c 27 00 20 01 00 00 00 58 fe 0e 27 00 fe 0c 08 00 20 01 00 00 00 58 fe 0e 08 00 38 c2 ff ff ff}  //weight: 10, accuracy: High
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "HMACSHA256" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SorvePotel_GDQ_2147959546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SorvePotel.GDQ!MTB"
        threat_id = "2147959546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SorvePotel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 05 11 06 11 04 11 06 91 08 11 06 08 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06 11 06 09 32 e1 11 05 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

