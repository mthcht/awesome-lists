rule Trojan_MSIL_Disfa_AC_2147780094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disfa.AC!MTB"
        threat_id = "2147780094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disfa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 04 6f ?? ?? ?? 0a 0d 06 09 28 ?? ?? ?? 0a ?? da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 11 04 17 d6 13 04 11 04 11 06 32 d1 06 28 ?? ?? ?? 0a 0a 06 2a}  //weight: 10, accuracy: Low
        $x_5_2 = "Pr0t3_DecrypT" ascii //weight: 5
        $x_4_3 = "FromBase64String" ascii //weight: 4
        $x_3_4 = "StrReverse" ascii //weight: 3
        $x_3_5 = "rawAssembly" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Disfa_ACH_2147781756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disfa.ACH!MTB"
        threat_id = "2147781756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disfa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "4FUG4aTaNniBGbtm0HvgHPCYbWCM9NCMfTignHBM5VDcbIzsbYDw4GAw4Gre9tig1VzguUdq0kj" ascii //weight: 3
        $x_3_2 = "tvQqaamaaaaeaaaa" ascii //weight: 3
        $x_3_3 = "FromBase64String" ascii //weight: 3
        $x_3_4 = "get_CurrentDomain" ascii //weight: 3
        $x_3_5 = "get_EntryPoint" ascii //weight: 3
        $x_3_6 = "UpToLowAndReverse" ascii //weight: 3
        $x_3_7 = "CompareString" ascii //weight: 3
        $x_3_8 = "Append" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disfa_AAJT_2147852779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disfa.AAJT!MTB"
        threat_id = "2147852779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disfa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 04 16 07 8e b7 17 da 13 07 13 05 2b 19 11 04 07 11 05 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 00 11 05 17 d6 13 05 11 05 11 07 13 09 11 09 31 dd}  //weight: 3, accuracy: Low
        $x_1_2 = "StrReverse" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disfa_SAW_2147922848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disfa.SAW!MTB"
        threat_id = "2147922848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disfa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 17 00 00 0a 0a 06 02 6f ?? ?? ?? 0a 6f 19 00 00 0a 0b 12 01 28 1a 00 00 0a 25 6f 1b 00 00 0a 26 6f 1c 00 00 0a 6f 1d 00 00 0a 6f ?? ?? ?? 0a 0c 12 02 28 1f 00 00 0a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Disfa_ZJAA_2147923419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Disfa.ZJAA!MTB"
        threat_id = "2147923419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disfa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1f 5a 28 00 02 00 06 13 0b 2b d6 07 1e 11 05 16 1e 28 ?? 00 00 0a 1f 62 28 04 02 00 06 13 0b 2b c0 00 1a 13 0b 2b ba 00 19 13 0b 2b b4 08 6f ?? 00 00 0a 1e 5b 8d 05 00 00 01 13 05 16 13 0b 2b a0 73 30 00 00 0a 13 06 1b 13 0b 2b 94}  //weight: 3, accuracy: Low
        $x_2_2 = {04 08 09 11 05 6f ?? 00 00 0a 16 73 62 00 00 0a 13 08 11 08 11 06 28 ?? 02 00 06 00 de 15}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

