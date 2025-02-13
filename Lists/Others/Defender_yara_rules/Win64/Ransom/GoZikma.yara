rule Ransom_Win64_GoZikma_PA_2147811431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoZikma.PA!MTB"
        threat_id = "2147811431"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoZikma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Go build ID: " ascii //weight: 1
        $x_1_2 = ".locked" ascii //weight: 1
        $x_3_3 = {0f b6 8c 04 ?? ?? ?? ?? 0f b6 54 04 ?? 31 d1 88 8c 04 ?? ?? ?? ?? 48 ff c0 48 3d ca 01 00 00 7c}  //weight: 3, accuracy: Low
        $x_3_4 = {0f b6 5c 04 ?? 31 da 88 94 04 ?? ?? ?? ?? 40 3d ca 01 00 00 7d}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

