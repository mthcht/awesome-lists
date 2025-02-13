rule Trojan_MSIL_Meterpreter_MBM_2147838095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Meterpreter.MBM!MTB"
        threat_id = "2147838095"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Gxjkw/GDA5jRUVHbRLv3uDQpdDhWi" wide //weight: 1
        $x_1_2 = "cKJoKrzO1ifoXVA3CmRQWxycQ5lVuClk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Meterpreter_MBN_2147838131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Meterpreter.MBN!MTB"
        threat_id = "2147838131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58}  //weight: 1, accuracy: High
        $x_1_2 = "$2059a686-3f50-409f-991c-cf05144d7d67" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Meterpreter_MBFG_2147849998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Meterpreter.MBFG!MTB"
        threat_id = "2147849998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 15 11 15 11 0e 11 12 7e ?? 00 00 0a 6f ?? 00 00 06 26 72 ?? ?? ?? 70 17 8d ?? 00 00 01 25 16 12 09 7c ?? 00 00 04 72 ?? 02 00 70 28 ?? 00 00 0a a2 13 1b 11 1b}  //weight: 1, accuracy: Low
        $x_1_2 = "hackedanyway" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Meterpreter_RP_2147913494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Meterpreter.RP!MTB"
        threat_id = "2147913494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Meterpreter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 6f 16 00 00 0a 74 1e 00 00 01 72 ?? 00 00 70 6f 17 00 00 0a a5 1f 00 00 01 76 6b 22 00 00 80 44 5b 22 00 00 80 44 5b 6c 0a 07 6f 18 00 00 0a 2d ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

