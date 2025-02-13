rule Ransom_MSIL_Ryzerlo_ARZ_2147850640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Ryzerlo.ARZ!MTB"
        threat_id = "2147850640"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ryzerlo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 0a 03 28 ?? ?? ?? 0a 0b 03 28 ?? ?? ?? 0a 0c 16 0d 2b 22 07 09 9a 28 ?? ?? ?? 0a 13 04 06 11 04 28 ?? ?? ?? 2b 2c 0a 02 07 09 9a 04 28 ?? ?? ?? 06 09 17 58 0d 09 07 8e 69 32 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

