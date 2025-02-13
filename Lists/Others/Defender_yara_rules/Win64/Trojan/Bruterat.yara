rule Trojan_Win64_Bruterat_PA_2147914222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bruterat.PA!MTB"
        threat_id = "2147914222"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bruterat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b c6 41 ff c1 4d 8d 52 ?? 48 f7 e1 48 8b c1 48 2b c2 48 d1 ?? 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 48 2b cb 0f b6 44 0c ?? 43 32 44 13 ?? 41 88 42 ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

