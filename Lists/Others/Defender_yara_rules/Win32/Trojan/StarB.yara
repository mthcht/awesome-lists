rule Trojan_Win32_StarB_2147785090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StarB"
        threat_id = "2147785090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StarB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 ?? ?? 8b f2 8b c1 83 e0 01 85 c0 75 ?? 8b c1 8b ?? ?? 03 d1 32 02 8b d3 03 d1 88 02 eb ?? 0f b6 ?? ?? 8b d6 2a c2 8b ?? ?? 03 d1 32 02 8b d3 03 d1 88 02 03 ?? ?? 0f b6 ?? 8b d3 03 d1 30 02 41 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

