rule VirTool_Win64_Threhijesz_A_2147918374_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Threhijesz.A!MTB"
        threat_id = "2147918374"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Threhijesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 c7 44 24 20 40 00 00 00 41 b9 00 10 00 00 41 b8 11 01 00 00 49 8b cf ?? ?? ?? ?? ?? ?? 41 b9 11 01 00 00 4c 89 6c 24 20 48 8b d0 ?? ?? ?? ?? ?? ?? ?? 49 8b cf 48 8b d8 [0-19] 48 89 9d 28 05 00 00 49 8b ce ?? ?? ?? ?? ?? ?? 49 8b ce [0-19] 33 c9 ?? ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 49 8b ce}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 44 24 38 44 3b c3 ?? ?? 33 d2 b9 ff ff 1f 00 ?? ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 44 39 6c 24 38}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 85 10 04 00 00 48 8b d6 83 e2 01 c7 44 24 60 0b 00 10 00 48 8b ce 48 d1 e9 48 ff c8 48 23 c8 48 8b 85 08 04 00 00 48 8b 0c c8 4c 8b 34 d1 49 8b ce [0-18] 49 8b ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

