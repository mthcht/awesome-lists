rule Trojan_Win32_Polyglot_SIB_2147807752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polyglot.SIB!MTB"
        threat_id = "2147807752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polyglot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 8d bd ?? ?? ?? ?? [0-32] 83 c4 18 33 c0 8a 0c 30 c0 f9 ?? 88 0c 47 8a 14 30 80 e2 ?? 88 54 47 ?? 40 3d ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 8d 49 ?? 33 c0 8b d1 c1 e2 ?? 03 d0 8a 14 3a 88 16 46 83 c0 02 83 f8 ?? 7c ?? 83 c1 02 83 f9 ?? 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {f9 ff ff 33 d2 8a 90 ?? ?? ?? ?? 83 f2 33 83 f2 33 8b 45 fc 88 90 00 8b 4d fc 83 c1 01 89 4d fc 81 7d fc 11 06 00 00 8b 45 fc 69 c0 b8 01 00 00 99 b9 dc 00 00 00 f7 f9 33 d2 8a 90 a4 00 41 00 83 f2 33 83 f2 33 8b 45 fc 88 90 a4 00 41 00 8b 4d fc 83 c1 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

