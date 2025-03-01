rule Trojan_MSIL_BitRat_MK_2147773856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRat.MK!MTB"
        threat_id = "2147773856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "taskperformer.src" ascii //weight: 10
        $x_10_2 = "select MACAddress, IPEnabled from Win32_NetworkAdapterConfiguration" ascii //weight: 10
        $x_1_3 = "7000720069006D006100720079005F006D00610069006E002E00700068007000" ascii //weight: 1
        $x_1_4 = "7300650063006F006E0064006100720079002E00700068007000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_BitRat_A_2147794212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRat.A!MTB"
        threat_id = "2147794212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Create" ascii //weight: 1
        $x_1_2 = "https://usdpedqpz.com/686" ascii //weight: 1
        $x_1_3 = "webRequest" ascii //weight: 1
        $x_1_4 = "GetResponse" ascii //weight: 1
        $x_1_5 = "CopyTo" ascii //weight: 1
        $x_1_6 = "SecurityProtocolType" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
        $x_1_9 = {11 04 11 05 11 04 11 05 91 20 ae 02 00 00 59 d2 9c 00 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 06 11 06 2d d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRat_NE_2147827659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRat.NE!MTB"
        threat_id = "2147827659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 0c 00 00 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 0a 06 6f ?? 00 00 0a 0b 07 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRat_NEA_2147829571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRat.NEA!MTB"
        threat_id = "2147829571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 03 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 58 0d 08 17 58 0c 2b de}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRat_NEB_2147830277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRat.NEB!MTB"
        threat_id = "2147830277"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 06 08 6f 15 00 00 0a 06 18 6f 16 00 00 0a 72 ?? 00 00 70 28 06 00 00 06 0d 06 6f 17 00 00 0a 09 16 09 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRat_NEAA_2147836091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRat.NEAA!MTB"
        threat_id = "2147836091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 2b 1b 00 7e 02 00 00 04 06 7e 02 00 00 04 06 91 20 6f 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 02 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: High
        $x_2_2 = "lucidsoftech" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BitRat_NEAC_2147844054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BitRat.NEAC!MTB"
        threat_id = "2147844054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BitRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "af3feeb4-1c71-4c48-878d-169f3315b855" ascii //weight: 5
        $x_2_2 = "miAeec.exe" ascii //weight: 2
        $x_1_3 = "SmartAssembly.HouseOfCards" ascii //weight: 1
        $x_1_4 = "set_CreateNoWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

