rule Trojan_MSIL_RaccoonStealerV2_A_2147852968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RaccoonStealerV2.A!MTB"
        threat_id = "2147852968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RaccoonStealerV2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 70 18 17 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 28 ?? ?? 00 0a 74 ?? 00 00 1b 13 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RaccoonStealerV2_B_2147893861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RaccoonStealerV2.B!MTB"
        threat_id = "2147893861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RaccoonStealerV2"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 09 16 6f ?? ?? 00 0a 13 04 12 04 28 ?? ?? 00 0a 13 05 08 11 05 6f ?? ?? 00 0a 09 17 58 0d 09 07 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

