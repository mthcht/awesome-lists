rule Trojan_MSIL_SalatStealer_AWNB_2147960259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SalatStealer.AWNB!MTB"
        threat_id = "2147960259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 2c 04 02 8e 2d 06 7e ?? 00 00 0a 2a 03 2d 0c 28 ?? 00 00 0a 02 6f ?? 00 00 0a 2a 02 8e 69 8d ?? 00 00 01 0a 16 0b 2b 0d 06 07 02 07 91 03 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ed 28 ?? 00 00 0a 06 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {06 18 5d 2d 07 28 ?? 00 00 06 2b 05 28 ?? 00 00 06 1f 64 07 1f 32 5a 58 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 07 19 32 d5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SalatStealer_SWQR_2147961051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SalatStealer.SWQR!MTB"
        threat_id = "2147961051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SalatStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 07 02 07 91 03 61 d2 9c 07 1f 0a 5d 2d 05 28 ?? ?? ?? 06 07 17 58 0b 07 02 8e 69 32 e2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

