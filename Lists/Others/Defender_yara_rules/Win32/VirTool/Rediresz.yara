rule VirTool_Win32_Rediresz_A_2147959258_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Rediresz.A"
        threat_id = "2147959258"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Rediresz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 85 db ?? ?? ?? ?? ?? ?? 8b 35 1c 50 40 00 68 1c 56 40 00 53 ff ?? 68 2c 56 40 00 53 a3 34 71 40 00 ff ?? 8b 9d 0c fd ff ff a3 30 71 40 00 8b 4b 04 51 83 ff 02}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 85 f6 ?? ?? 8b 0d 7c 50 40 00 ba 38 58 40 00 56 68 ?? 11 40 00 e8 ?? ?? ?? ?? 8b c8 ff ?? ?? ?? ?? ?? 8b c8 ff ?? ?? ?? ?? ?? ba f0 51 40 00 8b c8 e8 ?? ?? ?? ?? 8b ce e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

