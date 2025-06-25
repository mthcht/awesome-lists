rule Ransom_Win64_Crypmod_ARAX_2147944596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Crypmod.ARAX!MTB"
        threat_id = "2147944596"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Crypmod"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 0c 01 00 00 48 63 d0 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 10 8b 85 0c 01 00 00 48 63 c8 48 8b 85 ?? ?? ?? ?? 48 01 c8 83 f2 55 88 10 83 85 0c 01 00 00 ?? 8b 85 0c 01 00 00 3b 85 ?? ?? ?? ?? 7c bd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

