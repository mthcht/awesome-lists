rule Trojan_Win64_Posprefer_PP_2147977623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Posprefer.PP!MTB"
        threat_id = "2147977623"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Posprefer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {42 0f b6 3c 13 41 8b c2 83 e0 1f 45 69 c9 ?? ?? ?? ?? 41 81 c1 39 30 00 00 41 8b d1 c1 ea 10 41 32 14 07 40 32 d7 41 32 d3 44 0f b6 df 0f b6 c2 0f b6 84 04 ?? ?? ?? ?? 43 88 04 14 41 ff c2 44 3b d6 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

