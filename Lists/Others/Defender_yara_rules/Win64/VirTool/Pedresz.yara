rule VirTool_Win64_Pedresz_A_2147970301_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Pedresz.A"
        threat_id = "2147970301"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Pedresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 28 48 83 64 24 20 00 45 33 c9 45 33 c0 ba ff ff 1f 00 ?? ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8b d8 89 44 24 44 85 c0 [0-20] ff}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 5c 24 08 57 48 83 ec 20 48 8b 8a b8 00 00 00 48 8b da 48 8b 42 18 bf 01 00 00 c0 81 79 18 ?? ?? ?? ?? ?? ?? 48 85 c0 ?? ?? 83 79 10 04 ?? ?? 8b 08 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

