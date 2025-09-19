rule Trojan_MSIL_Hawkeye_DHB_2147748644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.DHB!MTB"
        threat_id = "2147748644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 09 1b 5b 93 6f ?? ?? ?? ?? 1f 0a 62 13 04 09 1b 5b 17 58 08 8e 69 fe 04 13 05 11 05 2c 14 11 04 06 08 09 1b 5b 17 58 93 6f ?? ?? ?? ?? 1b 62 60 13 04 09 1b 5b 18 58}  //weight: 1, accuracy: Low
        $x_1_2 = {08 8e 69 fe 04 13 06 11 06 2c 12 11 04 06 08 09 1b 5b 18 58 93 6f ?? ?? ?? ?? 60 13 04 20 ff 00 00 00 11 04 1f 0f 09 1b 5d 59 1e 59 1f 1f 5f 63 5f 13 04 07 11 04 d2 6f ?? ?? ?? ?? 00 00 09 1e 58 0d 09 02 6f ?? ?? ?? ?? 1b 5a fe 04 13 07 11 07 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Hawkeye_AFD_2147833489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AFD!MTB"
        threat_id = "2147833489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 9a 28 ?? ?? ?? 0a 9c 11 04 17 58 13 04 11 04 1f 18 32 e7}  //weight: 2, accuracy: Low
        $x_1_2 = "Split" ascii //weight: 1
        $x_1_3 = "GetTypeFromHandle" ascii //weight: 1
        $x_1_4 = "GetFields" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AIOW_2147833823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AIOW!MTB"
        threat_id = "2147833823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 d6 13 04 11 04 16 28 ?? ?? ?? 06 7e 01 00 00 04 d8 fe 04 13 06 11 06 2c 0b 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHE_2147840878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHE!MTB"
        threat_id = "2147840878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 58 20 00 01 00 00 5d 13 07 08 11 05 11 07 91 58 20 00 01 00 00 5d 0c 11 05 11 07 91 13 0b 11 05 11 07 11 05 08 91 9c 11 05 08 11 0b 9c 11 05 11 07 91 11 05 08 91 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHE_2147840878_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHE!MTB"
        threat_id = "2147840878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 0a 2b 37 02 50 06 02 50 8e b7 5d 02 50 06 02 50 8e b7 5d 91 03 06 03 8e b7 5d 91 61 02 50 06 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 06 17 d6 0a 06 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHE_2147840878_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHE!MTB"
        threat_id = "2147840878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 2b 20 09 65 1a 5d 2c 11 28 ?? ?? ?? 06 8e 69 1b 59 17 58 8d 05 00 00 01 0c 09 17 58 0d 09 1f 64 31 c1}  //weight: 2, accuracy: Low
        $x_1_2 = "socruA.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHE_2147840878_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHE!MTB"
        threat_id = "2147840878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 25 17 58 0c 12 00 28 ?? 00 00 0a 9c 07 08 25 17 58 0c 12 00 28 ?? 00 00 0a 9c 07 08 25 17 58 0c 12 00 28}  //weight: 2, accuracy: Low
        $x_1_2 = {16 0b 2b 10 06 07 02 02 8e 69 17 59 07 59 91 9c 07 17 58 0b 07 06 8e 69 fe 04 0d 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHW_2147849316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHW!MTB"
        threat_id = "2147849316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0a 2b 59 11 06 17 58 20 00 01 00 00 5d 13 06 08 11 04 11 06 91 58 20 00 01 00 00 5d 0c 11 04 11 06 91 13 0b 11 04 11 06 11 04 08 91 9c 11 04 08 11 0b 9c 11 04 11 06 91 11 04 08 91 58 20 00 01 00 00 5d 13 09 02 50 11 0a 02 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHW_2147849316_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHW!MTB"
        threat_id = "2147849316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 4b 02 8e b7 17 58 8d ?? 00 00 01 0a 16 13 04 16 02 8e b7 17 59 13 06 13 05 2b 34 06 11 05 02 11 05 91 09 61 08 11 04 91 61 9c 08 28 ?? 00 00 0a 11 04 08 8e b7 17 59 33 05 16 13 04 2b 06 11 04 17 58 13 04 11 05 17 58 13 05 2b 03 0c 2b b2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHW_2147849316_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHW!MTB"
        threat_id = "2147849316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 36 00 00 04 08 07 6f c3 00 00 0a 28 c5 00 00 0a 13 04 28 71 00 00 0a 11 04 16 11 04 8e 69 6f c3 00 00 0a 28 54 01 00 0a 13 05 7e 38 00 00 04 39 18 00 00 00 7e 37 00 00 04 02 11 05}  //weight: 2, accuracy: High
        $x_1_2 = "8d689f9b-f435-43e6-8f43-6e4eb6257f8e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHW_2147849316_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHW!MTB"
        threat_id = "2147849316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e b7 17 59 13 06 13 05 2b 2b 11 04 11 05 02 11 05 91 06 61 08 07 91 61 9c 08 28 ?? 00 00 0a 07 08 8e b7 17 59 33 04 16 0b 2b 04 07 17 58 0b 11 05 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {0d 0c 2b 46 07 08 91 1f 1f 31 24 07 08 91 1f 7f 2f 1d 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 08 1f 1f 5d 16 58 28 ?? 00 00 0a 59 d2 9c 07 08 91 1f 20 32 02 2b 0e 07 08 07 08 91 1f 5f 58 28 ?? 00 00 0a 9c 08 17 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHW_2147849316_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHW!MTB"
        threat_id = "2147849316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 06 8e b7 17 da 0d 0c 2b 3f 06 08 91 1f 1f fe 02 06 08 91 1f 7f fe 04 5f 2c 14 06 08 13 04 11 04 06 11 04 91 08 1f 1f 5d 18 d6 b4 59 86 9c 06 08 91 1f 20 2f 0f 06 08 13 04 11 04 06 11 04 91 1f 5f 58 86 9c 08 17 d6}  //weight: 1, accuracy: High
        $x_2_2 = {06 17 d6 20 00 01 00 00 5d 0a 08 11 08 06 91 d6 20 00 01 00 00 5d 0c 11 08 06 91 0b 11 08 06 11 08 08 91 9c 11 08 08 07 9c 11 08 06 91 11 08 08 91 d6 20 00 01 00 00 5d 13 05 02 50 11 0a 02 50 11 0a 91 11 08 11 05 91 61 9c 11 0a 17 d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHY_2147918875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHY!MTB"
        threat_id = "2147918875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 2b 16 0b 2b 13 02 06 02 06 91 7e 01 00 00 04 07 91 61 d2 9c 07 17 58 0b 07 7e 01 00 00 04 8e 69 fe 04 13 04 11 04 2d dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHK_2147919712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHK!MTB"
        threat_id = "2147919712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 8e b7 17 58 8d 0d 00 00 01 0a 16 13 04 16 02 8e b7 17 59 13 06 13 05 2b 34 06 11 05 02 11 05 91 09 61 07 11 04 91 61 9c 07 28 ?? 00 00 0a 11 04 07 8e b7 17 59 33 05 16 13 04 2b 06 11 04 17 58 13 04 11 05 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = {07 08 91 1f 1f 2b 4b 07 08 91 1f 7f 2b 3a 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 08 1f 1f 5d 17 58 28 ?? 00 00 0a 59 d2 9c 07 08 91 1f 20 2f 1a 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 1f 5f 58 d2 9c 2b 04 2f e1 2b c2 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHA_2147921661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHA!MTB"
        threat_id = "2147921661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 02 8e b7 17 da 13 06 13 05 2b 29 06 11 05 02 11 05 91 11 04 61 09 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da 33 04 16 0b 2b 04 07 17 d6 0b 11 05 17 d6 13 05 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AHM_2147922267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AHM!MTB"
        threat_id = "2147922267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 2d 02 2b 39 02 09 02 8e b7 5d 91 07 09 07 8e b7 5d 91 61 18 2d 40 26 02 09 02 8e b7 5d 08 02 09 17 d6 02 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 09 15 d6 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Hawkeye_AWH_2147938607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hawkeye.AWH!MTB"
        threat_id = "2147938607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hawkeye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 16 7e 03 00 00 04 06 7e 03 00 00 04 06 91 1f ?? 61 d2 9c 06 17 58 0a 06 7e 03 00 00 04 8e 69 32 e0}  //weight: 1, accuracy: Low
        $x_2_2 = {16 0c 2b 33 28 ?? 00 00 06 06 07 9a 6f ?? 00 00 0a 74 ?? 00 00 1b 0d 09 16 7e ?? 00 00 04 08 09 8e 69 17 59 28 ?? 00 00 0a 08 09 8e 69 58 0c 08 17 59 0c 07 17 58 0b 07 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

