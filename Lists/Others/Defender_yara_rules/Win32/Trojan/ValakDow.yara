rule Trojan_Win32_ValakDow_2147758892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ValakDow!MTB"
        threat_id = "2147758892"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ValakDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c1 66 2b d0 8b 44 24 10 66 83 c2 03 04 19 02 c0 66 89 15 ?? ?? ?? ?? 89 44 24 10 8b d3 83 44 24 20 04 8a c1 02 c0 8a e9 02 e8 8a 44 24 0f 02 c5 28 44 24 10 83 6c 24 38 01 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

