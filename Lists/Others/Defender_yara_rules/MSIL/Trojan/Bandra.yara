rule Trojan_MSIL_Bandra_GTA_2147836083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bandra.GTA!MTB"
        threat_id = "2147836083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 06 12 11 58 11 06 25 1f 3b 5c 1f 3b 5a 59 1f 38 58 11 06 12 11 58 46 61 52 11 06 17 58 13 06 11 06 1f 11 37 da}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "Project35.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bandra_ABW_2147836506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bandra.ABW!MTB"
        threat_id = "2147836506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 24 00 00 06 0a 06 28 29 00 00 0a 7d 30 00 00 04 06 02 7d 31 00 00 04 06 03 7d 32 00 00 04 06 15 7d 2f 00 00 04 06 7c 30 00 00 04 12 00 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bandra_NEAA_2147839972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bandra.NEAA!MTB"
        threat_id = "2147839972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6f 13 00 00 0a 8e 69 5d 91 06 08 91 61 d2 6f 14 00 00 0a 08 17 25 2c 17 58 16}  //weight: 10, accuracy: High
        $x_5_2 = "Xurttmptesy.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bandra_NEAB_2147840577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bandra.NEAB!MTB"
        threat_id = "2147840577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "5f16ab07-ed65-46a4-8842-d70ce0e94007" ascii //weight: 5
        $x_4_2 = "E:\\Aarons Stuff\\.NET Development\\_Projects\\FolderIT" wide //weight: 4
        $x_4_3 = "This assembly is protected by" wide //weight: 4
        $x_1_4 = "FolderCreator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bandra_AMAB_2147888787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bandra.AMAB!MTB"
        threat_id = "2147888787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 06 07 02 07 6f ?? 00 00 0a d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d e5}  //weight: 1, accuracy: Low
        $x_1_2 = {00 09 11 07 02 11 04 07 58 17 58 91 06 61 d2 9c 11 04 07 17 58 58 13 04 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 08 11 08 2d d4}  //weight: 1, accuracy: High
        $x_1_3 = {00 06 02 07 91 0c 12 02 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bandra_AMBC_2147902632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bandra.AMBC!MTB"
        threat_id = "2147902632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 91 04 03 1f ?? 5d 91 61 28 ?? ?? ?? ?? 05 03 17 58 05 8e 69 5d 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bandra_PGB_2147946607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bandra.PGB!MTB"
        threat_id = "2147946607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bandra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 12 00 28 ?? 00 00 0a 19 5b 18 5a 1f 14 58 28 ?? 00 00 0a 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 12 00 28 ?? 00 00 0a 19 5b 18 5a 1f 14 59 28 ?? 00 00 0a 00 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 30 00 36 00 2e 00 31 00 38 00 39 00 2e 00 31 00 38 00 39 00 2e 00 35 00 37 00 2f 00 [0-15] 00 7a 00 69 00 70}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

