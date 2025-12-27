rule Trojan_Win32_GandCrab_C_2147727994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.C"
        threat_id = "2147727994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 85 58 ff ff ff 78 cd b3 64 c7 85 90 fd ff ff 4f 3a 6d 4f c7 85 60 ff ff ff dd 16 f9 1c c7 85 94 fc ff ff 00 41 2c 4b c7 85 68 ff ff ff 5f 3a bf 7c c7 85 70 ff ff ff 87 48 fb 56 c7 85 78 ff ff ff d8 2e b2 2a}  //weight: 1, accuracy: High
        $x_1_2 = "vokogumiwubota hutucoza mevijihara" ascii //weight: 1
        $x_1_3 = "bemebopobozeharupuyuci tefuvukuyidediyejuyiwadutoxazepa yuwenesihuhosicefulecu" ascii //weight: 1
        $x_1_4 = {f7 e9 03 d1 c1 fa 04 8b c2 c1 e8 1f 03 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_GandCrab_B_2147741758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.B"
        threat_id = "2147741758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cmd.exe /c taskkill /f /im tor.exe" ascii //weight: 3
        $x_1_2 = ".onion" ascii //weight: 1
        $x_5_3 = "Release\\Varenyky.pdb" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GandCrab_PDSK_2147743506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.PDSK!MTB"
        threat_id = "2147743506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fd 43 03 00 6a 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? ff 15}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4d 08 a0 ?? ?? ?? ?? 30 04 0e 46 3b f7 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrab_DSK_2147744429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.DSK!MTB"
        threat_id = "2147744429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 55 fe 08 5d ?? 8a c2 83 25 ?? ?? ?? ?? 00 24 fc c0 e0 04 0a f8 81 3d ?? ?? ?? ?? 38 13 00 00 88 7d fc 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrab_VDSK_2147745355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.VDSK!MTB"
        threat_id = "2147745355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 05 c3 9e 26 00 a3 0a 00 69 05 ?? ?? ?? ?? fd 43 03 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 30 04 0e 46 3b f7 7c}  //weight: 1, accuracy: High
        $x_2_3 = {8b 45 d4 c1 e0 04 03 45 e4 8b 4d d4 03 4d ec 33 c1 8b 55 d4 c1 ea 05 03 55 e8 33 c2 8b 4d f4}  //weight: 2, accuracy: High
        $x_2_4 = {33 c4 89 84 24 00 08 00 00 a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 8d 0c 24 51 05 c3 9e 26 00 68 ?? ?? ?? ?? a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GandCrab_PVS_2147745359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.PVS!MTB"
        threat_id = "2147745359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 09 3c 04 00 8d 73 01 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af c6 69 c0 85 ba 03 00 a3 05 00 a1}  //weight: 2, accuracy: Low
        $x_1_2 = {30 04 3e 46 3b 74 24 10 7c 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 45 fc 43 94 0e 00 81 45 fc 80 0a 18 00 69 05 ?? ?? ?? ?? fd 43 03 00 03 45 fc a3}  //weight: 1, accuracy: Low
        $x_1_4 = {30 84 37 00 fe ff ff 6a 00 ff 15 05 00 e8}  //weight: 1, accuracy: Low
        $x_1_5 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 05 00 a1}  //weight: 1, accuracy: Low
        $x_2_6 = {8a 4a 03 8a c1 24 fc 8a d9 80 e1 f0 c0 e1 02 0a 0a c0 e0 04 0a 42 01 c0 e3 06 0a 5a 02 88 0c 3e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GandCrab_KDS_2147748119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.KDS!MTB"
        threat_id = "2147748119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cb 8b c3 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 1e 33 c8 2b f2 2b f9 45 83 fd 20 72}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 81 50 7c 42 00 8a 10 8d b6 50 7c 42 00 8a 1e 41 88 18 88 16 89 0d ?? ?? ?? ?? 3b cf 0f 85 16 00 8b 0d ?? ?? ?? ?? 81 25 ?? ?? ?? ?? ff 00 00 00 8b 35}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 8e d0 f7 b1 00 81 e7 ff 00 00 00 89 3d ?? ?? ?? ?? 8a 87 d0 f7 b1 00 88 86 d0 f7 b1 00 46 88 8f d0 f7 b1 00 89 35 d0 f8 b1 00 81 fe 00 01 00 00 0f 85 0c 00 8b 35 ?? ?? ?? ?? 8b 3d}  //weight: 2, accuracy: Low
        $x_2_4 = {8a 82 20 ea 42 00 8a 8e 20 ea 42 00 88 86 20 ea 42 00 88 8a 20 ea 42 00 0f b6 9e 20 ea 42 00 0f b6 c1 03 d8 81 fa 2e 0c 00 00 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrab_KSD_2147748121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.KSD!MTB"
        threat_id = "2147748121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 55 ff 88 90 a0 56 43 00 0f b6 b1 a0 56 43 00 0f b6 ca 03 f1 3d 2c 87 14 00 76}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 45 ff 88 99 ?? ?? ?? ?? 0f b6 9a ?? ?? ?? ?? 03 d8 81 f9 2c 87 14 00 76 0c 00 8b 0d ?? ?? ?? ?? 8b 15}  //weight: 2, accuracy: Low
        $x_2_3 = {8b cf 8b c7 c1 e9 05 03 4d f0 c1 e0 04 03 45 ec 33 c8 8d 04 3b 33 c8 8b 45 e8 2b f1 b9 01 00 00 00 2b c8 03 d9 83 6d fc 01 75}  //weight: 2, accuracy: High
        $x_2_4 = {8a 81 80 ef 42 00 8a 9a 80 ef 42 00 88 82 80 ef 42 00 81 f9 0a 0d 00 00 73 0c 00 8b 0d ?? ?? ?? ?? 8b 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrab_DVK_2147748124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.DVK!MTB"
        threat_id = "2147748124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4c 28 03 8a d9 8a f9 80 e3 f0 c0 e1 06 0a 4c 28 02 80 e7 fc c0 e3 02 0a 1c 28 c0 e7 04 0a 7c 28 01 81 3d ?? ?? ?? ?? be 00 00 00 88 4c 24 13 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 0c f5 04 00 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 03 cf be 20 37 ef c6 89 4d d4 89 75 f4 8b 09 89 4d f0 3d 2c 02 00 00 75 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 54 24 18 03 cb 8d 04 31 8a 0c 31 32 ca 43 81 fb ec 05 00 00 88 08 0f 8e 06 00 8b 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrab_KDV_2147748603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.KDV!MTB"
        threat_id = "2147748603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d3 c1 ea 05 03 54 24 1c 8b c3 c1 e0 04 03 44 24 20 8d 0c 2b 33 d0 33 d1 2b fa 81 fe 61 0e 00 00 73}  //weight: 2, accuracy: High
        $x_2_2 = {8b c6 c1 e8 05 03 45 e4 8b ce c1 e1 04 03 4d e0 33 c1 8d 0c 33 33 c1 2b f8 81 7d f0 1d 1e 00 00 73}  //weight: 2, accuracy: High
        $x_2_3 = {8b 00 40 8b 8d ?? fb ff ff 89 01 8b 4d fc 33 cd e8 ?? ?? ?? ?? 8b e5 5d c3 06 00 8b 85 ?? fb ff ff}  //weight: 2, accuracy: Low
        $x_2_4 = {8b ff 8b ca a3 ?? ?? ?? ?? 33 c1 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 8b ff 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_5 = "cGwLvA}$$WNN*hP5uV5pLcPxahwMLVKUDP@%LnfGG$WnHopvj$hdx3Q1fTdkCr#Q" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_GandCrab_PVK_2147749239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.PVK!MTB"
        threat_id = "2147749239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 0f b7 05 ?? ?? ?? ?? 25 ff 7f 00 00 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7 7c}  //weight: 1, accuracy: Low
        $x_2_3 = {8a 6c 38 03 8a cd 8a d5 80 e1 f0 c0 e5 06 0a 6c 38 02 80 e2 fc c0 e1 02 0a 0c 38 c0 e2 04 0a 54 38 01 81 3d ?? ?? ?? ?? be 00 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {89 c1 8d 44 3f 03 83 e0 fc e8 ?? ?? ?? ?? 89 d8 89 e3 83 e3 f0 89 dc 51 53 6a ff 50 6a 00 68 e9 fd 00 00}  //weight: 2, accuracy: Low
        $x_2_5 = {8a 5c 24 1f 8a 44 24 12 0a df 88 04 2e 81 3d ?? ?? ?? ?? 41 04 00 00 75 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_GandCrab_GD_2147753905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.GD!MTB"
        threat_id = "2147753905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 47 3b 7c 24 ?? 7c 04 00 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_GandCrab_AB_2147952694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GandCrab.AB!MTB"
        threat_id = "2147952694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GandCrab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 01 00 00 6a 00 66 c7 45 dc 74 00 f3 0f 7f 45 b4 c7 45 c4 6d 2e 62 69 66 c7 45 c8 74 00 c7 45 ec 67 64 63 62 c7 45 f0 2e 62 69 74 c6 45 f4 00 89 45 e8 ?? ?? ?? ?? ?? ?? 8b d8 89 5d fc 85 db ?? ?? ?? ?? ?? ?? 33 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

