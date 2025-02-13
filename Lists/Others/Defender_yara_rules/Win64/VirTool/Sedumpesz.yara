rule VirTool_Win64_Sedumpesz_A_2147847731_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Sedumpesz.A!MTB"
        threat_id = "2147847731"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Sedumpesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b8 34 02 00 00 48 ?? ?? ?? 48 8b d8 e8 ?? ?? ?? ?? 48 ?? ?? ?? 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 48 89 44 24 50 4c 89 74 24 58 ff 15 ?? ?? ?? ?? 4c ?? ?? ?? ?? ba ff 01 0f 00 48 8b c8 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 4c 24 48 4c 8d ?? ?? ?? 4c 89 74 24 28 41 b9 10 00 00 00 33 d2 4c 89 74 24 20 c7 44 24 68 01 00 00 00 c7 44 24 74 02 00 00 00 ff 15 ?? ?? ?? ?? 85 c0 75}  //weight: 1, accuracy: Low
        $x_1_4 = {ba 10 04 00 00 4c ?? ?? ?? ?? 48 ?? ?? ?? ?? e8 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b f8 ff 15 ?? ?? ?? ?? 48 8b 4c 24 40 41 b9 02 00 00 00 4c 89 74 24 30 8b d0 4c 89 74 24 28 4c 8b c7 4c 89 74 24 20 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

