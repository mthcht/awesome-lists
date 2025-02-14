rule Trojan_MSIL_SnakeStealer_NA_2147917726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeStealer.NA!MTB"
        threat_id = "2147917726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 58 04 09 91 52 09 17 58 0d 09 04 8e 69 32 ef}  //weight: 5, accuracy: High
        $x_4_2 = {06 11 06 11 08 58 91 07 11 08 91 2e 05 16 13 07 2b 0d 11 08 17 58 13 08 11 08 07 8e 69 32 e1}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeStealer_NC_2147917919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeStealer.NC!MTB"
        threat_id = "2147917919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {09 8e 69 5d 09 8e 69 58 09 8e 69 5d 91}  //weight: 3, accuracy: High
        $x_2_2 = {07 11 08 08 5d 08 58 08 5d 91 13 09 16 13 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeStealer_BL_2147933348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeStealer.BL!MTB"
        threat_id = "2147933348"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 16 0b 2b 0d 04 06 07 91 6f ?? 00 00 0a 07 17 58 0b 07 03 32}  //weight: 4, accuracy: Low
        $x_1_2 = {02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0a 06 05 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

