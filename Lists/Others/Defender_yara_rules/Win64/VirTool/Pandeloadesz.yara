rule VirTool_Win64_Pandeloadesz_A_2147922940_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pandeloadesz.A!MTB"
        threat_id = "2147922940"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pandeloadesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 40 00 00 00 ba 00 10 00 00 49 89 f9 48 89 c1 ?? ?? ?? ?? ?? ?? 85 c0 ?? ?? ba 00 10 00 00 48 89 f1 c7 06 48 33 c0 c3 49 89 f9 44 8b 44 24 3c [0-18] 41 b8 00 10 00 00 48 89 f2 48 89 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 42 0a 01 45 31 c9 45 31 c0 ba 01 00 00 00 c7 44 24 20 00 00 00 00 4c 89 d1 ?? ?? ?? ?? ?? ?? 48 89 c6 31 c0 48 85 f6 ?? ?? ?? ?? ?? ?? 45 31 c9 45 31 c0 48 89 f1 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 24 00 00 48 8b 94 24 b0 10 00 00 ?? ?? ?? ?? ?? ?? 48 85 c0 48 89 c7}  //weight: 1, accuracy: Low
        $x_1_3 = {30 01 41 ff 01 ?? ?? 41 ff c3 48 ff c1 41 80 fb 9b ?? ?? 41 c6 41 09 01 31 c9 4d 89 e9 c7 44 24 28 00 00 00 00 48 c7 44 24 20 00 00 00 00 ?? ?? ?? ?? ?? ?? 48 8b 4c 24 30}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 8b 44 24 68 48 89 c6 48 89 c2 48 89 e9 48 c7 44 24 20 00 00 00 00 4c 8b 4c 24 70 4d 29 c1 ?? ?? ?? ?? ?? ?? 48 8b 54 24 70 45 31 c9 41 b8 20 00 00 00 48 89 f1 48 2b 54 24 68 ?? ?? ?? ?? ?? ?? 45 31 c0 48 89 fa 48 89 f1 ?? ?? ?? ?? ?? ?? 48 89 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

