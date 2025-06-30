rule Trojan_MSIL_Umbral_ASZ_2147888126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Umbral.ASZ!MTB"
        threat_id = "2147888126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Umbral"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 2c 06 07 9a 0c 7e 4a 05 00 04 08 6f d0 02 00 0a 6f 05 02 00 0a 28 56 00 00 2b 2c 0d 08 6f d1 02 00 0a de 05 26 17 0d de 0c 07 17 58 0b 07 06 8e 69 32 ce}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Umbral_GA_2147915381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Umbral.GA!MTB"
        threat_id = "2147915381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Umbral"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "UMBRAL STEALER" ascii //weight: 10
        $x_1_2 = "://discord.com/api/webhooks/" ascii //weight: 1
        $x_5_3 = "://github.com/Blank-c/Umbral-Stealer" ascii //weight: 5
        $x_1_4 = "Webhook" ascii //weight: 1
        $x_1_5 = "Screenshot" ascii //weight: 1
        $x_1_6 = "Steal" ascii //weight: 1
        $x_1_7 = "builder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Umbral_AB_2147944984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Umbral.AB!MTB"
        threat_id = "2147944984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Umbral"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 61 13 1c 11 1d 02 7c 0f 00 00 04 7c 15 00 00 04 1e 58 4c 61 13 1d 11 1e 02 7c 10 00 00 04 7c 16 00 00 04 4c 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

