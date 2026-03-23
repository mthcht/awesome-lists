rule Trojan_Win64_MaskgramStealer_PGMS_2147965368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MaskgramStealer.PGMS!MTB"
        threat_id = "2147965368"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MaskgramStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 ed 4d 63 e4 8d 50 ?? 89 c8 42 32 14 23 32 14 2b 0f af c7 83 c0 3f 41 32 04 0b 31 c2 41 88 14 0a 41 83 f9 10 75 ?? 45 31 c9 48 ff c1 41 39 c8 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

