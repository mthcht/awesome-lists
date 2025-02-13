rule Ransom_AndroidOS_Boogr_A_2147834271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Boogr.A!MTB"
        threat_id = "2147834271"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Boogr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 02 60 03 69 00 35 03 2d 00 54 42 ?? 08 6e 10 ?? ?? 02 00 0a 02 3c 02 06 00 5c 41 ?? 08 12 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0c 00 1a 01 ?? ?? 12 32 23 22 e0 05 13 03 34 00 12 04 4f 03 02 04 13 03 0f 00 12 15 4f 03 02 05 12 23 12 76 4f 06 02 03 71 20 ?? ?? 21 00 0c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

