rule Trojan_MSIL_Dropper_CSC_2147808174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.CSC!MTB"
        threat_id = "2147808174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 07 91 03 07 91 fe 01 16 fe 01 0c 08 2c 02 16 0a 00 07 17 58 0b 07 02 8e 69 fe 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_SRK_2147809236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.SRK!MTB"
        threat_id = "2147809236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 02 13 06 11 06 13 05 11 05 72 17 00 00 70 28 ?? ?? ?? 0a 2d 2c 11 05 72 4d 00 00 70 28 ?? ?? ?? 0a 2d 2d 11 05 72 9b 00 00 70 28 ?? ?? ?? 0a 2d 2e 11 05 72 b1 00 00 70 28 ?? ?? ?? 0a 2d 2f 2b 3e 72 11 01 00 70 0b 07 28 ?? ?? ?? 0a 0a 2b 2f 72 fe df 05 70 0c 08 28 ?? ?? ?? 0a 0a 2b 20 72 0b 1b 07 70 0d 09 28 ?? ?? ?? 0a 0a 2b 11 72 20 76 0d 70 13 04 11 04 28 ?? ?? ?? 0a 0a 2b 00 06 28 ?? ?? ?? 06 0a 06 28 ?? ?? ?? 0a 13 07 de 07 26 00 14 13 07 de 00 11 07}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_PEGA_2147810534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.PEGA!MTB"
        threat_id = "2147810534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 87 00 00 70 28 ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 39 d7 00 00 00 06 28 ?? ?? ?? 0a 3a 81 00 00 00 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 7e 36 00 00 0a 72 a1 00 00 70 17 6f ?? ?? ?? 0a 0b 07 72 fd 00 00 70 72 21 01 00 70 06 72 21 01 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_NEGA_2147810537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.NEGA!MTB"
        threat_id = "2147810537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 09 07 5d 17 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 16 93 13 0c 11 0b 09 11 0c 28 ?? ?? ?? 0a 9e 11 0a 09 09 9e 12 03 28 ?? ?? ?? 0a 09 17 da 28 ?? ?? ?? 0a 26 00 09 20 ff 00 00 00 fe 02 16 fe 01 13 12 11 12 2d bb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_ZEGA_2147810538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.ZEGA!MTB"
        threat_id = "2147810538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 70 00 00 0a 0b 00 07 1f 10 8d 40 00 00 01 0c 08 16 17 9c 08 17 18 9c 08 18 19 9c 08 19 1a 9c 08 1a 1b 9c 08 1b 1c 9c 08 1c 1d 9c 08 1d 1e 9c 08 1e 1f 09 9c 08 1f 09 17 9c 08 1f 0a 18 9c 08 1f 0b 19 9c 08 1f 0c 1a 9c 08 1f 0d 1b 9c 08 1f 0e 1c 9c 08 1f 0f 1d 9c 08 6f ?? ?? ?? 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_NE_2147823572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.NE!MTB"
        threat_id = "2147823572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0b 00 00 0a 72 b4 0e 5d 70 6f 0c 00 00 0a 0a 73 0d 00 00 0a 0b 02 28 08 00 00 0a 73 0e 00 00 0a 0c 08 07 06 06 6f 0f 00 00 0a 16 73 10 00 00 0a 0d 09 73 11 00 00 0a 13 04 11 04 6f 12 00 00 0a 13 05 de 0a}  //weight: 1, accuracy: High
        $x_1_2 = "0ODy7dr26gBqdm5pR28llXdIdojyoHFgBsCLEeS4W81c7zUyEo59vZ5dwiV7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_PSK_2147831471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.PSK!MTB"
        threat_id = "2147831471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 0b 00 00 01 73 7d 00 00 0a 13 0e 11 0e 11 13 28 82 ?? ?? ?? 6f 7e ?? ?? ?? 07 11 0d 6f 7f ?? ?? ?? 73 80 ?? ?? ?? 13 14 06 6f 81 ?? ?? ?? 07 6f 82 ?? ?? ?? 16 73 83 ?? ?? ?? 13 15}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_4 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_5 = "GetPublicKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_PSJ_2147899274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.PSJ!MTB"
        threat_id = "2147899274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 28 12 00 00 06 28 27 ?? ?? ?? 13 06 11 05 11 06 16 11 06 8e 69 6f 28 ?? ?? ?? 00 11 05 6f 29 ?? ?? ?? 00 11 05 6f 2a ?? ?? ?? 00 00 de 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "GetTempPath" ascii //weight: 1
        $x_1_4 = "get_Assembly" ascii //weight: 1
        $x_1_5 = "ldklhdlj98fhv" wide //weight: 1
        $x_1_6 = "trafficlightyellow" wide //weight: 1
        $x_1_7 = "trafficlightgreen" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_PSP_2147899278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.PSP!MTB"
        threat_id = "2147899278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 8c 06 00 70 a2 28 36 ?? ?? ?? 6f 1f ?? ?? ?? 11 0f 16 6f 38 ?? ?? ?? 11 0f 17 6f 37 ?? ?? ?? 11 0f 28 3a ?? ?? ?? 20 e8 03 00 00 6f 3c ?? ?? ?? 26 72 3a 06 00 70 73 3b ?? ?? ?? 13 0f 11 0f 1b 8d 21 00 00 01 25}  //weight: 5, accuracy: Low
        $x_1_2 = "schtasks" wide //weight: 1
        $x_1_3 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dropper_ABW_2147913940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dropper.ABW!MTB"
        threat_id = "2147913940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 59 9c 11 06 13 07 06 11 07 73 ?? ?? ?? 0a 13 08 11 05 11 08 11 05 6f ?? ?? ?? 0a 8e b7 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 05 11 08 11 05 6f ?? ?? ?? 0a 8e b7 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 13 09 11 09 11 05 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 0a 11 04 28 ?? ?? ?? 0a 13 0b 11 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

