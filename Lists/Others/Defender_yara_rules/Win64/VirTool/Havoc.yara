rule VirTool_Win64_Havoc_E_2147929297_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Havoc.E"
        threat_id = "2147929297"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Havoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 d1 48 89 c8 45 31 c0 44 0f b6 08 41 ff c0 48 83 c0 04 47 8a 0c 0c 44 88 48 fc 41 80 f8 04 ?? ?? 48 ff c1 49 39 cd ?? ?? 8a 4c 24 35 8a 44 24 31 88 4c 24 31 8a 4c 24 39 88 4c 24 35 8a 4c 24 3d 88 44 24 3d 8a 44 24 32 88 4c 24 39 8a 4c 24 3a 88 44 24 3a 8a 44 24 36 88 4c 24 32 8a 4c 24 3e 88 44 24 3e 8a 44 24 33 88 4c 24 36 8a 4c 24 3f 88 4c 24 33 8a 4c 24 3b 88 4c 24 3f 8a 4c 24 37 88 44 24 37 88 4c 24 3b 41 83 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {43 8a 34 02 45 8a 04 12 41 8a 14 02 43 8a 04 0a 45 89 d9 41 c1 e9 03 42 32 34 0b 41 89 f1 ?? ?? 83 fe 04 ?? ?? 47 8a 0c 0a 47 8a 04 02 41 8a 14 12 41 8a 04 02 44 32 09 44 32 41 01 41 ff c3 48 83 c1 04 32 51 fe 32 41 ff 44 88 49 1c 44 88 41 1d 88 51 1e 88 41 1f 41 83 fb 3c ?? ?? 5b 5e c3}  //weight: 1, accuracy: Low
        $x_1_3 = {48 81 ec f8 04 00 00 48 8d 7c 24 78 44 89 8c 24 58 05 00 00 48 8b ac 24 60 05 00 00 4c 8d 6c 24 78 f3 ab b9 59 00 00 00 48 c7 44 24 70 00 00 00 00 c7 44 24 78 68 00 00 00 c7 84 24 b4 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

