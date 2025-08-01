rule Trojan_MSIL_BPLogger_AKXA_2147944422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BPLogger.AKXA!MTB"
        threat_id = "2147944422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BPLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 00 11 02 02 11 02 91 03 11 02 11 01 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 4, accuracy: Low
        $x_2_2 = {11 02 17 58 13 02 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BPLogger_ALBB_2147948134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BPLogger.ALBB!MTB"
        threat_id = "2147948134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BPLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 05 11 09 6f ?? 00 00 0a 13 0a 72 60 07 00 70 12 0a 28 ?? 00 00 0a 8c ?? 00 00 01 12 0a 28 ?? 00 00 0a 8c ?? 00 00 01 12 0a 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 13 0b 11 0b 6f ?? 00 00 0a 1c fe 01 13 0c}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 11 05 20 ff 00 00 00 5d 8c ?? 00 00 01 a2 25 17 11 05 18 5a 20 ff 00 00 00 5d 8c ?? 00 00 01 a2 25 18 11 05 19 5a 20 ff 00 00 00 5d 8c ?? 00 00 01 a2 25 19 11 05 1a 5a 20 ff 00 00 00 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

