rule Trojan_MSIL_Cobaltstrike_PSLC_2147845495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PSLC!MTB"
        threat_id = "2147845495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 33 00 00 70 28 ?? ?? ?? 0a 0b 00 28 08 00 00 06 0c 06 18 73 ?? ?? ?? 0a 13 05 00 11 05 08 16 08 8e 69 6f ?? ?? ?? 0a 00 00 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_EH_2147846270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.EH!MTB"
        threat_id = "2147846270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1.0.8469.6745" wide //weight: 1
        $x_1_2 = "Chrome.exe" wide //weight: 1
        $x_1_3 = "rangeDecoder" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_PSNH_2147847078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PSNH!MTB"
        threat_id = "2147847078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 02 7b 01 00 00 04 72 c4 10 00 70 07 6f 05 00 00 06 28 ?? ?? ?? 0a 02 7b 01 00 00 04 6f 06 00 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_PSUI_2147852524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PSUI!MTB"
        threat_id = "2147852524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 72 59 02 00 70 28 ?? 00 00 0a 0a 06 72 ab 02 00 70 28 ?? 00 00 0a 0a 06 72 ab 02 00 70 72 3f 02 00 70 6f ?? 00 00 0a 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_PSVT_2147888816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PSVT!MTB"
        threat_id = "2147888816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 07 08 6f ?? 00 00 0a 16 73 1a 00 00 0a 13 06 00 73 1b 00 00 0a 13 07 00 20 00 04 00 00 8d 0a 00 00 01 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_PSWJ_2147889356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PSWJ!MTB"
        threat_id = "2147889356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 06 6f ?? 00 00 0a 26 06 6f ?? 00 00 0a 0b 72 1f 00 00 70 0c 07 08 6f ?? 00 00 0a 00 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_PSWT_2147890093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PSWT!MTB"
        threat_id = "2147890093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 8e 69 8d 03 00 00 01 0a 16 0b 38 13 00 00 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 3f e4 ff ff ff 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_PSQO_2147899412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PSQO!MTB"
        threat_id = "2147899412"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 26 00 00 0a 26 28 ?? ?? ?? 0a 03 03 6f ?? ?? ?? 0a 02 16 02 8e 69 6f ?? ?? ?? 0a 72 6f 01 00 70 28 23 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_PTIQ_2147902886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.PTIQ!MTB"
        threat_id = "2147902886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 03 16 06 03 8e 69 28 ?? 00 00 0a 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobaltstrike_AFR_2147924450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobaltstrike.AFR!MTB"
        threat_id = "2147924450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 fe 01 0a 06 2c 0e 00 72 e3 00 00 70 28 26 00 00 0a 0b 2b 0d 72 fd 00 00 70 28 26 00 00 0a 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

