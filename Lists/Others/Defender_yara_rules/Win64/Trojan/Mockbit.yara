rule Trojan_Win64_Mockbit_AA_2147906290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mockbit.AA!MTB"
        threat_id = "2147906290"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 ff 00 00 00 0f b6 c9 03 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 0f b6 44 24 ?? 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 0f b7 44 24 ?? 66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 0f b7 4c 24 ?? 3b c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

