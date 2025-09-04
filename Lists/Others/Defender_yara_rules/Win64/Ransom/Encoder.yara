rule Ransom_Win64_Encoder_KK_2147951396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Encoder.KK!MTB"
        threat_id = "2147951396"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Encoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {44 89 d0 99 f7 fe 48 63 d2 41 0f b6 04 14 42 30 04 13 49 83 c2 01 4c 39 d7 75}  //weight: 20, accuracy: High
        $x_10_2 = "files have been encrypted" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

