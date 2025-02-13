rule Trojan_MSIL_Coins_ABVX_2147847207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coins.ABVX!MTB"
        threat_id = "2147847207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0d 07 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 2d ea dd ?? 00 00 00 08 39 ?? 00 00 00 08 6f ?? 00 00 0a dc 07 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coins_AAFQ_2147851343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coins.AAFQ!MTB"
        threat_id = "2147851343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 06 16 06 8e 69 6f ?? 01 00 0a 0b 07 16 fe 02 13 06 11 06 2c 0b 11 05 06 16 07 6f ?? 00 00 0a 00 16 13 07 2b 2e 00 03 7e ?? 00 00 04 03 7b ?? 00 00 04 06 11 07 91 61 20 ff 00 00 00 5f 95 03 7b ?? 00 00 04 1e 64 61 7d ?? 00 00 04 00 11 07 17 58 13 07 11 07 6e 07 6a fe 04 13 08 11 08 2d c5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coins_AAQR_2147892026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coins.AAQR!MTB"
        threat_id = "2147892026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 01 00 06 7e ?? 00 00 04 06 07 28 ?? 01 00 06 7e ?? 00 00 04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 19 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? 01 00 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Coins_KAA_2147900306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Coins.KAA!MTB"
        threat_id = "2147900306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Coins"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 fe 0c 01 00 fe 0c 02 00 fe 09 00 00 fe 0c 02 00 6f ?? 00 00 0a fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 8e 69 5d 91 61 d2 9c 00 fe 0c 02 00 20 ?? 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 6f ?? 00 00 0a fe 04 fe 0e 03 00 fe 0c 03 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

