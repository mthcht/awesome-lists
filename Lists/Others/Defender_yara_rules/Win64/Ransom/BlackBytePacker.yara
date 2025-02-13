rule Ransom_Win64_BlackBytePacker_SA_2147888537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/BlackBytePacker.SA!MTB"
        threat_id = "2147888537"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "BlackBytePacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 f7 e8 d1 fa 8b c2 c1 e8 ?? 03 d0 41 8b c4 66 2b c2 0f b7 c0 6b c8 ?? 66 41 ?? ?? 41 ?? ?? 66 41 ?? ?? ?? 41 83 f8 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

