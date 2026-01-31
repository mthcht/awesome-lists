rule Ransom_Win64_Shirna_YBG_2147962108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Shirna.YBG!MTB"
        threat_id = "2147962108"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Shirna"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 20 8b 17 01 ?? c7 44 24 ?? 6a 66 38 ef c7 44 24 ?? 6d b7 53 50}  //weight: 1, accuracy: Low
        $x_4_2 = {32 d8 8b d6 0f b6 c3 69 c8 ?? ?? ?? ?? 8b 45 fc 32 c8 89 4d 0c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

