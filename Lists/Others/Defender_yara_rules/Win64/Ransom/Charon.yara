rule Ransom_Win64_Charon_ARR_2147962693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Charon.ARR!MTB"
        threat_id = "2147962693"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Charon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {33 d1 8b ca 03 c1 33 44 24 ?? 8b 0c 24 83 c1}  //weight: 12, accuracy: Low
        $x_8_2 = {33 c8 8b c1 8b 8c 24 ?? ?? ?? ?? 03 c8 8b c1 8b 0c 24 83 c1 ?? 8b c9 48 8b 94 24}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

