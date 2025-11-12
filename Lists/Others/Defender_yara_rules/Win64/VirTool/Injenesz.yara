rule VirTool_Win64_Injenesz_A_2147957268_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Injenesz.A"
        threat_id = "2147957268"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Injenesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 66 c7 44 24 40 48 b8 48 89 44 24 42 ?? ?? ?? ?? ?? ?? ?? c5 fb 10 44 24 40 66 89 44 24 4a 8b 44 24 48 89 44 24 60 c5 fb 11 44 24 58 4c 89 74 24 5a 66 c7 44 24 62}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 45 e7 41 b9 08 00 00 00 [0-19] 66 c7 45 9f 4c b8 41 b9 02 00 00 00 ?? ?? ?? ?? 48 8b 55 f7 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 b9 08 00 00 00 ?? ?? ?? ?? 48 8b 55 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

