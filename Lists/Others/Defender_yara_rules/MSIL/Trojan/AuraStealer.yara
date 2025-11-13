rule Trojan_MSIL_AuraStealer_AUKB_2147957435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AuraStealer.AUKB!MTB"
        threat_id = "2147957435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AuraStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 14 fe 03 13 07 11 07 2c 2a 11 04 08 6f ?? ?? 00 0a 00 11 04 08 6f ?? ?? 00 0a 00 11 04 6f ?? ?? 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? ?? 00 0a 0a de 53 00 de 4b}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

