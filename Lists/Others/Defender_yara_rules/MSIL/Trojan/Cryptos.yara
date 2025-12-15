rule Trojan_MSIL_Cryptos_MS_2147774363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptos.MS!MTC"
        threat_id = "2147774363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptos"
        severity = "Critical"
        info = "MTC: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LILJAJMKGIHMMORF" ascii //weight: 1
        $x_1_2 = "DvExbzFB" ascii //weight: 1
        $x_1_3 = "Buttonsa" ascii //weight: 1
        $x_1_4 = "Narfilak" ascii //weight: 1
        $x_1_5 = "AssemblyTrademarkAttribute" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
        $x_1_7 = "GetManifestResourceStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cryptos_PHR_2147934487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptos.PHR!MTB"
        threat_id = "2147934487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 72 01 00 00 70 28 ?? 00 00 0a 72 33 00 00 70 ?? 14 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 dd 29}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cryptos_SK_2147952366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptos.SK!MTB"
        threat_id = "2147952366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 13 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cryptos_SM_2147959473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cryptos.SM!MTBB"
        threat_id = "2147959473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cryptos"
        severity = "Critical"
        info = "MTBB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elnhwkfu.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "$6225a3a6-9305-416e-9f6f-a0324f15d6ef" ascii //weight: 1
        $x_1_3 = "If5sLhRjg5Q=" ascii //weight: 1
        $x_1_4 = "hhmQeuBd6xBAnC0ZcdYjhA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

