rule Trojan_MSIL_LimeRAT_NEA_2147829569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LimeRAT.NEA!MTB"
        threat_id = "2147829569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 18 18 28 ?? 00 00 06 0b 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 74 ?? 00 00 01 0c 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LimeRAT_NEC_2147832294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LimeRAT.NEC!MTB"
        threat_id = "2147832294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 5f 03 66 05 5f 60 58 0e 07 0e 04 e0 95 58 7e bb 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 cd 02 00 06 58 54 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LimeRAT_A_2147833973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LimeRAT.A!MTB"
        threat_id = "2147833973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 0a 06 02 7d ?? 00 00 04 06 7b ?? 00 00 04 17 6f ?? 00 00 0a 06 fe}  //weight: 2, accuracy: Low
        $x_2_2 = {01 0a 02 16 06 16 1f 10 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 07 07 06 25 13 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a 09 6f ?? 00 00 0a 08 6f}  //weight: 2, accuracy: Low
        $x_2_3 = {0a 0a 02 16 28 ?? 00 00 0a 0b 06 02 1a 02 8e 69 1a 59 6f ?? 00 00 0a 07 8d ?? 00 00 01 0c 06 16 6a 6f ?? 00 00 0a 06 16 73 ?? 00 00 0a 08 16 08 8e 69 6f}  //weight: 2, accuracy: Low
        $x_1_4 = "WriteAllBytes" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LimeRAT_MAAJ_2147848150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LimeRAT.MAAJ!MTB"
        threat_id = "2147848150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$7e562bc1-2e63-4a25-a235-e919f6c9e03b" ascii //weight: 1
        $x_1_2 = "ConsoleApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

