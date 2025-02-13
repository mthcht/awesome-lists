rule VirTool_WinNT_Wspipe_A_2147575682_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Wspipe.A"
        threat_id = "2147575682"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Wspipe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {68 44 64 6b 20 68 00 08 00 00 6a 01 ff 15 ?? ?? 01 00 8b d8 85 db 74 5d 56 57 53 ff 75 0c ff 75 08 e8 85 fc ff ff 53 ff 15 ?? ?? 01 00 8b 35 14 1f 01 00 59 bf 10 1f 01 00 3b f7 74 19 ff 76 fc 53 ff 15 ?? ?? 01 00 59 85 c0 59 75 05 8b 76 04 eb e7 c6 45 ff 01 53}  //weight: 6, accuracy: Low
        $x_6_2 = {68 44 64 6b 20 68 00 08 00 00 6a 01 32 db ff 15 ?? ?? 01 00 8b f8 85 ff 74 59 55 56 57 6a 00 ff 74 24 1c e8 98 fd ff ff 57 ff 15 ?? ?? 01 00 8b 35 14 1f 01 00 59 bd 10 1f 01 00 3b f5 74 17 ff 76 fc 57 ff 15 ?? ?? 01 00 59 85 c0 59 75 05 8b 76 04 eb e7 b3 01 57}  //weight: 6, accuracy: Low
        $x_6_3 = {68 44 64 6b 20 68 00 08 00 00 6a 01 32 db ff 15 ?? ?? 01 00 8b f8 85 ff 74 5b 55 56 57 ff 74 24 1c ff 74 24 1c e8 12 fd ff ff 57 ff 15 ?? ?? 01 00 8b 35 14 1f 01 00 59 bd 10 1f 01 00 3b f5 74 17 ff 76 fc 57 ff 15 ?? ?? 01 00 59 85 c0 59 75 05 8b 76 04 eb e7 b3 01 57}  //weight: 6, accuracy: Low
        $x_6_4 = {50 ff 75 08 e8 f6 fe ff ff 8d 45 80 50 e8 6b ff ff ff 8b 1d dc 13 01 00 8d 45 80 50 8d 45 c0 50 ff d3 59 85 c0 59 74 30 8b 35 24 1f 01 00 bf 20 1f 01 00 3b f7 74 21 ff 76 fc 8d 45 c0 50 ff d3 59 85 c0 59 74 05 8b 76 04 eb e8 80 3d 80 14 01 00 00 74 04 33 c0 eb 0c ff 75 0c ff 75 08 ff 15 ?? ?? 01 00 5f 5e 5b c9 c2 08 00}  //weight: 6, accuracy: Low
        $x_3_5 = "{b63bff8c-2e25-4ccc-9a01-68807f567aa7}" wide //weight: 3
        $x_3_6 = "{09e76a33-92ea-407e-a05a-fbf3833bc492}" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_6_*) and 1 of ($x_3_*))) or
            ((4 of ($x_6_*))) or
            (all of ($x*))
        )
}

