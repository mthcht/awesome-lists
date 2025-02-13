rule Trojan_MSIL_Miner_KA_2147896234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Miner.KA!MTB"
        threat_id = "2147896234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Miner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 91 0c 07 1e 5d 0d 03 09 9a 13 04 02 07 11 04 08 28 ?? 00 00 06 9c 07 17 d6 0b 07 06 31 e0}  //weight: 10, accuracy: Low
        $x_10_2 = {08 1f 0f 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 ec}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Miner_HNA_2147907537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Miner.HNA!MTB"
        threat_id = "2147907537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Miner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_25_1 = {25 57 00 61 00 74 00 63 00 68 00 64 00 6f 00 67 00 20 00 52 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 3a 00 20 00 00 ?? 47 00 6c 00 6f 00 62 00 61 00 6c 00}  //weight: 25, accuracy: Low
        $x_25_2 = {4d 00 69 00 6e 00 65 00 72 00 73 00 3a 00 00}  //weight: 25, accuracy: High
        $x_50_3 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 47 65 74 53 74 72 69 6e 67 00 53 79 73 74 65 6d 2e 4d 61 6e 61 67 65 6d 65 6e 74 00 43 6f 6e 6e 65 63 74 69 6f 6e 4f 70 74 69 6f 6e 73 00 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 00 73 65 74 5f 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 00 4d 61 6e 61 67 65 6d 65 6e 74 53 63 6f 70 65}  //weight: 50, accuracy: High
        $x_10_4 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 10, accuracy: High
        $x_10_5 = {00 49 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 4c 65 76 65 6c 00}  //weight: 10, accuracy: High
        $x_10_6 = "SELECT Name, VideoProcessor FROM Win32_VideoController" ascii //weight: 10
        $x_10_7 = {00 43 6f 6e 6e 65 63 74 69 6f 6e 4f 70 74 69 6f 6e 73 00}  //weight: 10, accuracy: High
        $x_5_8 = {00 4d 61 6e 61 67 65 6d 65 6e 74 53 63 6f 70 65 00}  //weight: 5, accuracy: High
        $x_5_9 = {00 4d 61 6e 61 67 65 6d 65 6e 74 4f 62 6a 65 63 74 43 6f 6c 6c 65 63 74 69 6f 6e 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((1 of ($x_25_*) and 2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_25_*) and 3 of ($x_10_*))) or
            ((2 of ($x_25_*))) or
            ((1 of ($x_50_*))) or
            (all of ($x*))
        )
}

