rule Ransom_Win64_GoSnatch_NG_2147976088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/GoSnatch.NG!MTB"
        threat_id = "2147976088"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "GoSnatch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4a 89 04 1f 48 8b 84 24 ?? ?? 00 00 48 83 c0 10 48 8b 9c 24 ?? ?? 00 00 48 ff cb 49 89 c8 89 f1 4c 89 c6 48 85 db}  //weight: 2, accuracy: Low
        $x_2_2 = {48 89 94 24 ?? ?? 00 00 48 89 bc 24 ?? ?? 00 00 48 89 9c 24 ?? ?? 00 00 88 8c 24 c6 00 00 00 48 89 b4 24 ?? ?? 00 00 48 89 84 24 ?? ?? 00 00 48 8b 10 48 89 94 24 ?? ?? 00 00 48 8b 58 08 48 89 9c 24 ?? 00 00 00 48 89 d0 48 8d 4c 24 ?? bf 10 00 00 00 be 20 00 00 00 4c 8b 84 24 ?? ?? 00 00 49 89 f9 49 89 f2}  //weight: 2, accuracy: Low
        $x_1_3 = "Encrypt" ascii //weight: 1
        $x_1_4 = "WriteTo" ascii //weight: 1
        $x_1_5 = "Go build" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

