rule Trojan_MSIL_NetWire_AD_2147775614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWire.AD!MTB"
        threat_id = "2147775614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetProxy" wide //weight: 1
        $x_1_2 = "NetWire" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\NetWire" ascii //weight: 1
        $x_1_4 = "encryptedUsername" ascii //weight: 1
        $x_1_5 = "encryptedPassword" ascii //weight: 1
        $x_1_6 = "encrypted_key" ascii //weight: 1
        $x_1_7 = "Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NetWire_RD_2147832521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWire.RD!MTB"
        threat_id = "2147832521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "SELECT * FROM Win32_Processor" wide //weight: 2
        $x_2_2 = "Select * from AntivirusProduct" wide //weight: 2
        $x_2_3 = "SELECT * FROM Win32_DisplayConfiguration" wide //weight: 2
        $x_2_4 = "Select * From Win32_ComputerSystem" wide //weight: 2
        $x_3_5 = {28 97 00 00 0a 73 98 00 00 0a 20 20 02 00 00 6f 99 00 00 0a 2a}  //weight: 3, accuracy: High
        $x_3_6 = {7e a5 00 00 0a 72 ?? ?? ?? ?? 17 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 17 6f a6 00 00 0a 72 ?? ?? ?? ?? 6f a7 00 00 0a 38 ?? ?? ?? ?? dd 16 00 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NetWire_NWQ_2147835150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWire.NWQ!MTB"
        threat_id = "2147835150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61}  //weight: 1, accuracy: High
        $x_1_2 = "OIY54Y55ZBEQ44GF4F57N5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NetWire_NWE_2147844513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWire.NWE!MTB"
        threat_id = "2147844513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 6f 3a 00 00 0a 25 26 0c 1f 61 6a 08 28 ?? 00 00 06 25 26 0d 09 28 3b 00 00 0a 25}  //weight: 5, accuracy: Low
        $x_1_2 = "add_ResourceResolve" ascii //weight: 1
        $x_1_3 = "WindowsApplication1.My" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NetWire_CSWO_2147846468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWire.CSWO!MTB"
        threat_id = "2147846468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 03 00 8e 69 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 59 5f 62 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 59 20 20 00 00 00 20 e5 1d d8 79 59 20 00 00 e0 03 20 cb 6c 72 75 20 1f 00 00 00 5f 62 20 00 00 e0 03 20 20 00 00 00 20 cb 6c 72 75 59 20 1f 00 00 00 5f 64 60 5f 64 60 5a}  //weight: 5, accuracy: Low
        $x_1_2 = "M?ain?F?o?r?m" wide //weight: 1
        $x_1_3 = "zIzmmezdizaztzelzyzThey" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NetWire_MAAQ_2147848458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWire.MAAQ!MTB"
        threat_id = "2147848458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 11 05 11 08 16 32 10 08 11 08 1f 27 58 1f 4e 5d 6f ?? 00 00 0a 2b 05 11 04 11 05 93 9d 11 05 17 58 13 05 11 05 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NetWire_NNW_2147892300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWire.NNW!MTB"
        threat_id = "2147892300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 03 11 00 8e 69 5d 91 7e ?? 00 00 04 11 03 91 61 d2 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Fljezeu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

