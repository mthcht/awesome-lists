rule Trojan_MSIL_EternityWorm_A_2147836961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EternityWorm.A!MTB"
        threat_id = "2147836961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EternityWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 20 ?? ?? 00 00 28 ?? ?? 00 06 a2 25 17 20 ?? ?? 00 00 28 ?? ?? 00 06 a2 14 14 14 28 ?? ?? 00 06 28 ?? 00 00 0a 13 01 38 0f 00 04 14 20 ?? ?? 00 00 28 ?? 02 00 06 18 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_EternityWorm_RDB_2147849148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EternityWorm.RDB!MTB"
        threat_id = "2147849148"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EternityWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0c 0c 00 1f 15 62 fe 0c 14 00 59 fe 0c 0c 00 61 fe 0c 16 00 59}  //weight: 2, accuracy: High
        $x_1_2 = "eebd50f4-8cdc-4aba-8ffe-db1722d76aed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

