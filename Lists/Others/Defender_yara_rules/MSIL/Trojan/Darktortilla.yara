rule Trojan_MSIL_Darktortilla_NB_2147918800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darktortilla.NB!MTB"
        threat_id = "2147918800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darktortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 1f 49 61 b4 0a 18 0d 2b b5 02 0a 18 0d 2b af}  //weight: 5, accuracy: High
        $x_5_2 = {26 16 0d 2b d0 03 1d 5d 16 fe 01 0b 07}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darktortilla_NA_2147927149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darktortilla.NA!MTB"
        threat_id = "2147927149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darktortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {93 61 1f 5c 5f 9d fe 02 2b 01 17 0a 06 2c 05 19 13 06 2b 87 18 2b f9}  //weight: 2, accuracy: High
        $x_1_2 = {91 61 20 c7 00 00 00 5f 9c 2c 05 17 13 04 2b a3 16}  //weight: 1, accuracy: High
        $x_1_3 = {91 61 1f 4e 5f 9c 2d 09 1f 0a 13 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Darktortilla_ZUU_2147942759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darktortilla.ZUU!MTB"
        threat_id = "2147942759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darktortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0c 00 08 07 28 ?? 01 00 06 0d 09 02 28 ?? 01 00 06 00 08 6f ?? 00 00 0a 0a de 24 00 09 2c 07 09 6f ?? 00 00 0a 00 dc 00 08 2c 07 08}  //weight: 6, accuracy: Low
        $x_5_2 = {a2 02 03 17 da 9a 28 ?? 00 00 0a 28 ?? 00 00 06 0a 02 03 1c da 06 a2 02 03 1d da 06 6f ?? 01 00 0a 1f 18 9a a2 02 03 1d da 9a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

