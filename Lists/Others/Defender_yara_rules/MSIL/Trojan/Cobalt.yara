rule Trojan_MSIL_Cobalt_MA_2147811902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobalt.MA!MTB"
        threat_id = "2147811902"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 08 02 16 15 00 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a [0-5] 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 09 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {13 08 11 08 07 16 07 8e 69 6f ?? ?? ?? 0a 11 08 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 80 ?? 00 00 04 11 07 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {e3 f8 aa 20 96 42 18 e0 c5 2e 0c 1e 0b 5e c4 ce}  //weight: 1, accuracy: High
        $x_1_4 = "ProcessCmdKey" ascii //weight: 1
        $x_1_5 = "FlushFinalBlock" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CreateInstance" ascii //weight: 1
        $x_1_11 = "set_UseMachineKeyStore" ascii //weight: 1
        $x_1_12 = "GetBytes" ascii //weight: 1
        $x_1_13 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobalt_KA_2147892122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobalt.KA!MTB"
        threat_id = "2147892122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 1f 40 2e 13 11 04 1f 5e 2e 39 2b 6c 06 09 1f 31 6f ?? 00 00 0a 2b 61 06 09 1f 32}  //weight: 10, accuracy: Low
        $x_1_2 = "NcqevkYEUtMb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cobalt_KAA_2147892127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cobalt.KAA!MTB"
        threat_id = "2147892127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobalt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 24 1d 11 09 5f 91 13 1c 11 1c 19 62 11 1c 1b 63 60 d2 13 1c 11 05 11 09 11 05 11 09 91 11 1c 61 d2 9c 11 09 17 58 13 09 11 09 11 07 32 d1}  //weight: 5, accuracy: High
        $x_5_2 = {11 28 11 0c 11 0d 11 0c 91 9d 17 11 0c 58 13 0c 11 0c 11 1a 32 ea}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

