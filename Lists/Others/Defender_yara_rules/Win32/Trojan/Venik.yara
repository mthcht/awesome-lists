rule Trojan_Win32_Venik_SIB_2147787621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Venik.SIB!MTB"
        threat_id = "2147787621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Venik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f8 ff 74 ?? 3b c6 7e ?? 53 8d 85 ?? ?? ?? ?? 56 50 e8 ?? ?? ?? ?? [0-5] 8d 85 02 56 53 50 8b 45 ?? ff 70 ?? ff 15 ?? ?? ?? ?? 8b f8 3b fe 7e ?? 8d 85 02 57 50 8b 44 24 ?? 33 c9 39 4c 24 ?? 7e ?? 8a 14 01 80 ea ?? 80 f2 ?? 88 14 01 41 3b 4c 24 0d 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 04 33 c9 39 4c 24 ?? 7e ?? 8a 14 01 80 f2 ?? 80 c2 ?? 88 14 01 41 3b 4c 24 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

