rule Trojan_MSIL_InjectorNetT_AGHA_2147929009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.AGHA!MTB"
        threat_id = "2147929009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0a 02 00 00 58 20 09 02 00 00 59 1e 59 1e 58 03 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorNetT_AMHA_2147929152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.AMHA!MTB"
        threat_id = "2147929152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 a0 00 00 0a 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b dd}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_InjectorNetT_APHA_2147929225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/InjectorNetT.APHA!MTB"
        threat_id = "2147929225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "InjectorNetT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 04 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c de 1e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

