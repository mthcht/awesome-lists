rule Spammer_Win32_Chopanez_A_2147604979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Chopanez.gen!A"
        threat_id = "2147604979"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Chopanez"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 4b b8 64 00 00 00 e8 ?? ?? ff ff 83 f8 0a 7d 3c b8 1a 00 00 00 e8 ?? ?? ff ff 8b d0 83 c2 61 8d 45 ec e8 ?? ?? ff ff ff 75 f0 68 ?? ?? 40 00 ff 75 ec 68 ?? ?? 40 00 ff 75 ec}  //weight: 2, accuracy: Low
        $x_2_2 = {eb 0a 68 60 ea 00 00 e8 ?? ?? ff ff 2d 00 83 3d ?? ?? 40 00 00 7e 30 33 c0 a3 ?? ?? 40 00 33 c0 a3 ?? ?? 40 00 33 c0}  //weight: 2, accuracy: Low
        $x_4_3 = {0f 87 85 00 00 00 ff 24 85 ?? 83 40 00 8b 6f 04 3b 6f 08 74 76 8d 45 1c 50 8d 4e 4c e8 ?? ?? ff ff 8b 47 08 83 c5 38 3b e8 75 ea}  //weight: 4, accuracy: Low
        $x_1_4 = "&sent=" ascii //weight: 1
        $x_1_5 = "&lost=" ascii //weight: 1
        $x_1_6 = "&drop=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

