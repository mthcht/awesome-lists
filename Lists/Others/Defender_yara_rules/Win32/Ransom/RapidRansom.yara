rule Ransom_Win32_RapidRansom_YAA_2147923372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RapidRansom.YAA!MTB"
        threat_id = "2147923372"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RapidRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d0 8b 4d 08 8b 55 ?? 01 ca 0f b6 12 89 d1 8b 55 f4 31 ca 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

