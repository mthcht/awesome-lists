rule Trojan_MSIL_Jaik_VDB_2147967555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jaik.VDB!MTB"
        threat_id = "2147967555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 0d 11 12 11 0d 72 0d 01 00 70 28 31 00 00 0a 7d 35 00 00 04 11 12 11 0d 72 39 01 00 70 28 31 00 00 0a 7d 36 00 00 04 11 12 7b 35 00 00 04 28 1a 00 00 06 11 12 7b 36 00 00 04}  //weight: 5, accuracy: High
        $x_1_2 = "CrimeOutput.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jaik_VDD_2147970990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jaik.VDD!MTB"
        threat_id = "2147970990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 6f 2b 00 00 0a 06 6f 2c 00 00 0a 72 7d 00 00 70 0b 07 72 86 0b 00 70 03 6f 2d 00 00 0a 0b 25 07 6f 2e 00 00 0a 25 6f 2f 00 00 0a 26 72 92 0b 00 70 0b 07 72 86 0b 00 70 03 6f 2d 00 00 0a 0b 25 07 6f 2e 00 00 0a 6f 2f 00 00 0a 26 de 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jaik_VDC_2147973039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jaik.VDC!MTB"
        threat_id = "2147973039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7e 01 00 00 04 11 1b 7e 01 00 00 04 8e 69 5d 91 61 d2 9c 00 11 1b 17 58 13 1b}  //weight: 5, accuracy: High
        $x_1_2 = "BypassAllAntivirus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jaik_VDJ_2147975317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jaik.VDJ!MTB"
        threat_id = "2147975317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 7d 00 00 70 09 73 0c 00 00 0a 7a 73 0d 00 00 0a 13 04 11 04 72 b3 00 00 70 6f 0e 00 00 0a 00 11 04 72 c3 00 00 70 09 72 e5 00 00 70 28 0f 00 00 0a}  //weight: 5, accuracy: High
        $x_1_2 = "PayloadChunks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jaik_VDH_2147975381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jaik.VDH!MTB"
        threat_id = "2147975381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OrdinaryWorldboxLauncher.Resources.Injector.exe" wide //weight: 2
        $x_2_2 = "OrdinaryWorldboxLauncher.Resources.SandboxHook.dll" wide //weight: 2
        $x_1_3 = "ForceLoadMods.dll" wide //weight: 1
        $x_1_4 = "rmdir /s /q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Jaik_VDI_2147975383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Jaik.VDI!MTB"
        threat_id = "2147975383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Jaik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 07 91 9d 07 7e 1f 00 00 04 58 0b 07 02 28 ?? 00 00 06 32 e9}  //weight: 5, accuracy: Low
        $x_5_2 = {7e 1e 00 00 04 0a 02 0b 16 0c 2b 0c 07 08 91 26 06 17 58 0a 08 17 58 0c 08 07 8e 69 32 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

