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

rule Trojan_MSIL_BPLogger_ZDP_2147949196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BPLogger.ZDP!MTB"
        threat_id = "2147949196"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BPLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {26 02 11 04 11 0a 6f ?? 00 00 0a 13 0b 04 03 6f ?? 00 00 0a 59 13 0c 11 0c 13 0e 11 0e 13 0d}  //weight: 6, accuracy: Low
        $x_4_2 = {2b 2c 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 2b 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BPLogger_ENZX_2147949721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BPLogger.ENZX!MTB"
        threat_id = "2147949721"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BPLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 06 7b 1c 00 00 04 09 23 00 00 00 00 00 00 00 40 ?? ?? ?? ?? ?? 09 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 02 6c 5b ?? ?? ?? ?? ?? 5a 03 5a a1 07 06 7b 1c 00 00 04 09 99 06 7b 1c 00 00 04 09 99 5a 58 0b 00 09 17 58 0d 09 02 fe 04 13 04 11 04 2d af}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BPLogger_EFAY_2147949724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BPLogger.EFAY!MTB"
        threat_id = "2147949724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BPLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 11 11 12 9a 13 13 00 09 11 13 ?? ?? ?? ?? 0a ?? ?? ?? ?? ?? 16 fe 01 13 16 11 16 2c 05 38 b6 00 00 00 09 11 13 ?? ?? ?? ?? 0a ?? ?? ?? ?? ?? 13 14 12 15 12 14 ?? ?? ?? ?? ?? 11 13 ?? ?? ?? ?? ?? 13 17 12 17 ?? ?? ?? ?? ?? 11 13 ?? ?? ?? ?? ?? 72 4a 26 00 70 ?? ?? ?? ?? ?? 2d 03 17 2b 01 15 5a 58 12 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

