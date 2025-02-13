rule VirTool_Win32_Alanloader_A_2147832001_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Alanloader.A"
        threat_id = "2147832001"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Alanloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 56 51 57 53 52 ba 20 00 00 00 33 ff 8b 75 08 8b 4d 0c 33 db ac 84 c0 ?? ?? c1 cf 13 3c 61 0f 4d da 2a c3 0f b6 c0 03 f8 ?? ?? 8b c7 5a 5b 5f 59 5e 8b e5 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 0c 8b 40 14 89 45 fc 89 45 f8 8d ?? ?? 8b 7b 04 85 ff ?? ?? 0f b7 0b 03 f9 fd 33 c0 b0 5c 8b f7 f2 ae fc ?? ?? 83 c7 02 89 7d f4 2b f7 56 57}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 55 fc 8b 72 20 03 75 08 8b 5d f8 8d ?? ?? 8b 3e 03 7d 08 33 c0 8b f7 b9 12 05 00 00 fc f2 ae 2b fe 4f 57 56}  //weight: 1, accuracy: Low
        $x_1_4 = {d1 e1 83 c1 68 83 c1 2c 8b f0 51 6a 04 68 00 30 00 00 51 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

