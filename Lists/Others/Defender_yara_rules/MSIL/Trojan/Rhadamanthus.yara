rule Trojan_MSIL_Rhadamanthus_CAK_2147840408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthus.CAK!MTB"
        threat_id = "2147840408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 16 13 04 2b 1c 09 11 04 18 5b 07 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df}  //weight: 3, accuracy: Low
        $x_2_2 = "cleaning.homesecuritypc.com/packages/Cmlvguceki.png" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthus_ARD_2147846022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthus.ARD!MTB"
        threat_id = "2147846022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 17 13 06 38 ?? ?? ?? 00 11 05 09 11 06 a3 07 00 00 01 6f ?? ?? ?? 0a 11 06 17 58 13 06 11 06 09 8e 69 32 e4 06 11 04 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthus_ABYX_2147848678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthus.ABYX!MTB"
        threat_id = "2147848678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 0d 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 0b dd ?? 00 00 00 26 de d6 07 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthus_AAUQ_2147894637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthus.AAUQ!MTB"
        threat_id = "2147894637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 11 03 16 28 ?? 13 00 06 13 07 20 09 00 00 00 38 ?? ff ff ff 16 13 03 20 05 00 00 00 38 ?? ff ff ff 12 07 28 ?? 06 00 0a 13 05 20 02 00 00 00 38 ?? ff ff ff 73 ?? 05 00 0a 13 02 20 03 00 00 00 38 ?? ff ff ff 11 03 17 58 13 03 20 07 00 00 00 38 ?? ff ff ff 11 03 11 01 28 ?? 13 00 06 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthus_ABQD_2147896716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthus.ABQD!MTB"
        threat_id = "2147896716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0b 07 6f ?? ?? ?? 0a 17 58 19 5b 0c 08 8d ?? ?? ?? 01 0d 16 13 05 2b 71 00 07 19 11 05 5a 6f ?? ?? ?? 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06 07 19 11 05 5a 17 58 6f ?? ?? ?? 0a 13 07 11 07 1f 39 fe 02 13 09 11 09 2c 0d 11 07 1f 41 59 1f 0a 58 d1 13 07 2b 08 11 07 1f 30 59 d1 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

