rule Trojan_MSIL_PhantomStealer_APH_2147955276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomStealer.APH!MTB"
        threat_id = "2147955276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 02 7d ?? 00 00 04 00 06 7b ?? 00 00 04 14 fe 01 13 0c 11 0c 2c 05 38 ?? 00 00 00 06 7b ?? 00 00 04 6f ?? 00 00 0a 0b 06 06 7b ?? 00 00 04 6f ?? 00 00 0a 7d ?? 00 00 04 07 06 7b ?? 00 00 04 5a 19 5a 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PhantomStealer_APN_2147955823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PhantomStealer.APN!MTB"
        threat_id = "2147955823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PhantomStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 08 11 1b 11 19 1d 5d 1f 1f 5f 62 11 19 1f 61 5a 61 61 13 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

