rule Trojan_MSIL_Hesv_NITA_2147925787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hesv.NITA!MTB"
        threat_id = "2147925787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hesv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 89 00 00 00 00 28 ?? 00 00 06 00 72 01 00 00 70 13 67 06 6f ?? 00 00 0a 13 68 11 67 28 ?? 00 00 0a 13 69 11 67 28 ?? 00 00 0a 13 6a 11 6a 8e 69 6a 13 6b 28 ?? 00 00 0a 11 69 6f ?? 00 00 0a 13 6c 11 68 11 6c 16 11 6c 8e 69 6f ?? 00 00 0a 00 11 6b 28 ?? 00 00 0a 13 6d 11 68 11 6d 16 11 6d 8e 69 6f ?? 00 00 0a 00 11 68 11 6a 16 11 6a 8e 69 6f ?? 00 00 0a 00 11 68 11 6a 16 11 6a 8e 69 6f ?? 00 00 0a 00 11 66 17 58 13 66 00 11 66 11 65 fe 04 13 6e 11 6e 3a 68 ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {00 73 25 00 00 0a 13 04 00 11 04 06 03 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 07 8d 33 00 00 01 13 06 16 13 08 2b 0f 00 11 06 11 08 1f 41 9c 00 11 08 17 58 13 08 11 08 11 06 8e 69 fe 04 13 09 11 09 2d e3 1f 0a 13 07 16 13 0a 2b 17 00 11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 00 00 11 0a 17 58 13 0a 11 0a 11 07 fe 04 13 0b 11 0b 2d dd 11 05 6f ?? 00 00 0a 00 08 17 58 0c 09 17 58 0d 00 de 0d 11 04 2c 08 11 04 6f ?? 00 00 0a 00 dc 00 09 04 fe 04 13 0c 11 0c 3a 60 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Hesv_ARJA_2147931724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hesv.ARJA!MTB"
        threat_id = "2147931724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hesv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0b}  //weight: 3, accuracy: High
        $x_2_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hesv_AHE_2147940162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hesv.AHE!MTB"
        threat_id = "2147940162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hesv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0b 16 0c 38 ?? 00 00 00 06 6f ?? 00 00 0a 08 a3 ?? 00 00 01 6f ?? 00 00 0a 18 40 ?? 00 00 00 07 16 06 6f ?? 00 00 0a 08 a3 ?? 00 00 01 6f ?? 00 00 0a a4 ?? 00 00 01 07 18 8f ?? 00 00 01 25 50 06 6f ?? 00 00 0a 08 a3 ?? 00 00 01 6f ?? 00 00 0a 72 ?? 13 00 70 28 ?? 00 00 0a 51 06 6f ?? 00 00 0a 08 a3 ?? 00 00 01 6f}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 16 0b 38 29 00 00 00 06 07 a3 ?? 00 00 01 0c 08 6f ?? 00 00 0a 39 12 00 00 00 08 6f ?? 00 00 0a 6f ?? 00 00 0a 10 00 38 0a 00 00 00 07 17 58 0b 07 06 8e 69 32 d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

