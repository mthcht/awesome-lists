rule Trojan_MSIL_Raccoon_A_2147794525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.A!MTB"
        threat_id = "2147794525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "liMjooLaYdlVujHtyCZzCwMcbAQpA" ascii //weight: 1
        $x_1_2 = "xcCyF" ascii //weight: 1
        $x_1_3 = "3sRcacuuo8T4z.resources" ascii //weight: 1
        $x_1_4 = "get_StartupPath" ascii //weight: 1
        $x_1_5 = "GetFolderPath" ascii //weight: 1
        $x_1_6 = "GetHashCode" ascii //weight: 1
        $x_1_7 = "ZipArchiveMode" ascii //weight: 1
        $x_1_8 = "IsLogging" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Raccoon_TX_2147796644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.TX!MTB"
        threat_id = "2147796644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Alexx\\Desktop\\msmsmsmsm.pdb" ascii //weight: 1
        $x_1_2 = "Aweiiwi.exe" wide //weight: 1
        $x_1_3 = "ODgzZGUyZTM5NzJlZmVlNw==$QXNzZW1ibHkgaGFzIGJlZW4gdGFtcGVyZWQ=" ascii //weight: 1
        $x_1_4 = "VGhlIHByb2dyYW0gY2FuJ3Qgc3RhcnQgYmVjYXVzZSBsaWJ3aW5wdGhyZWFkLTEuZGxsI" ascii //weight: 1
        $x_1_5 = "Q29yb25vdmlydXMuQ29yb25vdmlydXM=" ascii //weight: 1
        $x_1_6 = "5nIHRoZSBwcm9ncmFtIHRvIGZpeCB0aGlzIHByb2JsZW0u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Raccoon_RC_2147837605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.RC!MTB"
        threat_id = "2147837605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 09 09 1f 64 30 03 16 2b 01 17 0e 00 07 07 d8 20 ?? ?? ?? ?? d8 28}  //weight: 3, accuracy: Low
        $x_1_2 = "Vehicle Management Database.accdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Raccoon_AR_2147838079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.AR!MTB"
        threat_id = "2147838079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 2b 6a 00 28 04 00 00 06 73 1a 00 00 0a 0b 73 15 00 00 0a 0c 07 16 73 1b 00 00 0a 73 1c 00 00 0a 0d 09 08 6f 17 00 00 0a de 0a 09 2c 06 09 6f 1d 00 00 0a dc 08 6f 18 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Raccoon_CND_2147842012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.CND!MTB"
        threat_id = "2147842012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 6f d2 03 00 0a 17 73 ?? ?? ?? ?? 0c 08 02 16 02 8e 69 6f ?? ?? ?? ?? 08}  //weight: 5, accuracy: Low
        $x_1_2 = "Debugger Detected" wide //weight: 1
        $x_1_3 = "_RunPe" ascii //weight: 1
        $x_1_4 = "Find" wide //weight: 1
        $x_1_5 = "ResourceA" wide //weight: 1
        $x_1_6 = "Virtual" wide //weight: 1
        $x_1_7 = "Alloc" wide //weight: 1
        $x_1_8 = "Write" wide //weight: 1
        $x_1_9 = "Process" wide //weight: 1
        $x_1_10 = "Memory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Raccoon_NRC_2147842651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.NRC!MTB"
        threat_id = "2147842651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 c7 00 00 06 06 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 7e ?? 00 00 04 08 07 16 73 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "internal.annotations.GuardedBy.module23" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Raccoon_PSIS_2147844985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.PSIS!MTB"
        threat_id = "2147844985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 28 6e 00 00 0a 25 26 0b 28 6f 00 00 0a 07 16 07 8e 69 6f 70 00 00 0a 25 26 0a 28 16 00 00 0a 06 6f 1d 00 00 0a 0c 1f 61 6a 08 28 90 00 00 06 25 26 80 31 00 00 04 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Raccoon_ABXU_2147847772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Raccoon.ABXU!MTB"
        threat_id = "2147847772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Raccoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1a 58 4a 02 8e 69 5d 7e ?? 00 00 04 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? 00 00 06 02 06 1a 58 4a 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 06 1a 58 4a 6a 02 8e 69 17 59 6a 06 4b 17 58 6e 5a 31 9c 0f 00 02 8e 69 17 59 28 ?? 00 00 2b 02 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

