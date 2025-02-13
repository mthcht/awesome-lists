rule Trojan_MSIL_Inject_SRPX_2147836806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Inject.SRPX!MTB"
        threat_id = "2147836806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 18 2b b4 08 17 58 0c 19 2b ad 2b ca 07 73 3c 00 00 0a 28 ?? ?? ?? 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Inject_NEAS_2147836974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Inject.NEAS!MTB"
        threat_id = "2147836974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Inject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 0a 06 8e 69 20 00 30 00 00 1f 40 28 ?? 00 00 06 13 04 09 11 04 06 06 8e 69 12 01 28 ?? 00 00 06 13 05 11 05 13 07 11 07 2c 2d 00 20 fb 03 00 00 16 08}  //weight: 10, accuracy: Low
        $x_5_2 = "APCInject.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

