rule Trojan_Win32_EmotetCrypt_A_2147762934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.A!MTB"
        threat_id = "2147762934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 8b 4d f4 03 4d ec 0f b6 11 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 08 8b 55 08 0f b6 04 0a 8b 0d ?? ?? ?? ?? 8b 11 8b 4d f4 0f b6 14 11 33 c2 8b 0d ?? ?? ?? ?? 8b 11 8b 4d 14 88 04 11 e9 ?? ff ff ff 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 02 8b 0d ?? ?? ?? ?? 8b 11 8b 4c 24 1c 8a 1c 0a 8a 04 28 8b 15 ?? ?? ?? ?? 8b 0a 8b 54 24 28 32 c3 88 04 0a a1 ?? ?? ?? ?? 8b 4c 24 20 40 3b c1 a3 ?? ?? ?? ?? 0f 82 ?? ?? ff ff 5f 5e 5d 5b 83 c4 08 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 08 8b 15 ?? ?? ?? ?? 8b 02 8b 54 24 20 8a 0c 29 32 0c 10 a1 ?? ?? ?? ?? 8b 10 8b 44 24 2c 88 0c 10 a1 ?? ?? ?? ?? 83 c0 01 3b 44 24 24 a3 ?? ?? ?? ?? 0f 82 ?? ?? ff ff 5f 5e 5d 5b 83 c4 0c c3}  //weight: 1, accuracy: Low
        $x_1_4 = {0f b6 04 0f 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b ea 8b 54 24 1c 8a 14 10 32 14 29 8b 6c 24 2c 88 14 28 a1 ?? ?? ?? ?? 40 3b c3 a3 ?? ?? ?? ?? 72 9d 5f 5e 5d 5b 83 c4 08 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 0c 37 88 04 37 88 0c 33 0f b6 04 37 0f b6 c9 03 c1 8b 4d 08 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8a 0c 08 32 0c 32 8b 55 18 88 0c 10 ff 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 45 0c 72 ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {55 8b 6c 24 10 2b 6c 24 14 56 57 8b c3 8d 70 01 8d 49 00 8a 10 83 c0 01 84 d2 75 f7 2b c6 8b f8 8b 44 24 1c 8d 34 01 33 d2 8b c1 f7 f7 83 c1 01 8a 14 1a 32 14 2e 3b 4c 24 20 88 16 75 cd 5f 5e 5d 5b c3}  //weight: 1, accuracy: High
        $x_1_7 = {f7 f6 8b fa 8a 14 29 8a 04 0f 88 14 0f 88 04 29 0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 0f b6 04 0a 8b 54 24 18 32 44 1a ff 83 6c 24 24 01 88 43 ff 75 ?? 5f 5e 5d 5b 83 c4 0c c3}  //weight: 1, accuracy: Low
        $x_1_8 = {f7 f1 8a 0c 32 89 55 fc 8d 04 32 8a 14 33 88 10 88 0c 33 0f b6 00 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 4d 14 8a 04 32 32 04 39 88 07 47 ff 4d 18 75 ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 45 1c 0f af 45 1c 03 d0 89 55 ec 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 4d 08 03 4d e4 0f b6 11 8b 45 f4 03 45 ec 0f b6 08 8b 45 1c 0f af 45 1c 03 c8 33 d1 8b 4d 18 03 4d e4 88 11 e9 ?? ff ff ff 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_10 = {33 d2 f7 f1 8a 0c 32 02 4d 17 89 55 fc 8d 04 32 8a 55 17 02 17 88 10 88 0f 0f b6 00 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b fa 03 7d 1c ff 15 ?? ?? ?? ?? 8a 04 37 8b 4d 18 02 45 17 32 04 19 88 03 43 ff 4d 0c 75 ?? 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_11 = {8a 04 3b 8a 0c 2f 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 4c 24 30 8a 44 24 28 03 d1 8b 4c 24 2c 8a 14 3a 02 d0 8b 44 24 24 32 14 01 40 89 44 24 24 88 50 ff 8b 44 24 20 48 89 44 24 20 0f 85 ?? ?? ff ff 5f 5e 5d 5b 83 c4 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBQ_2147763494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBQ!MTB"
        threat_id = "2147763494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 0f b6 04 0a 8b 54 24 ?? 32 44 1a ?? 83 6c 24 ?? 01 88 43}  //weight: 1, accuracy: Low
        $x_1_2 = "<6Tu6xLRyyntnR_h_>Y)!Nfq^nGN2M(CRJKT_zpXwOuc<HvX__tb$Dd1S**l(cem*GwC3$_!9?cE@9VJFe2y2" ascii //weight: 1
        $x_1_3 = "fGbK>QJPPWu@AaUr_zdgweA8D6K9$>ZBU1cl$j70vJLJ)w6)U(o9c>%Dc)J!R4ORadVBJsD)aM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBR_2147763573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBR!MTB"
        threat_id = "2147763573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 15 ?? ?? ?? ff 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 8d ?? ?? ?? ff 0f b6 84 15 ?? ?? ?? ff 32 44 1f ff ff 4d ?? 88 43 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 54 3c ?? 0f b6 c0 03 c2 99 f7 fb 0f b6 44 14 ?? 32 44 29 ff 83 6c 24 ?? 01 88 41 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 44 3c 18 81 e2 ff 00 00 00 03 c2 99 f7 fb 8a 1c 29 8a 44 14 18 32 c3 88 01}  //weight: 1, accuracy: High
        $x_1_4 = "p!aa(x<LT2x9%5vd$Z9WDy$9L*qUkxH4cB8it" ascii //weight: 1
        $x_1_5 = "ZLG_(d657IAuISrKGE7<W0y6uP%@@$bo!KFVTcA1qWMHjN%voi1tAw4w5^4M>6!?gU_ijNJNR_xB$@Yv+!mqgG5mdw!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBS_2147763763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBS!MTB"
        threat_id = "2147763763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ET1Q96rlBAAABvXdhZeI5RT.pdb" ascii //weight: 1
        $x_1_2 = "N5fG0lxr5znuHf8xGWulbG_6" ascii //weight: 1
        $x_1_3 = "CreateMutexW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBT_2147763944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBT!MTB"
        threat_id = "2147763944"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 29 8a 01 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f3 8a 01 47 41 8a 1c 32 88 04 32 88 59 ff 8b 1d ?? ?? ?? ?? 3b fb 89 54 24 10 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 0c 2e 0f b6 c0 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 20 8b da 03 d8 ff 15 ?? ?? ?? ?? 8a 14 33 8a 44 24 28 8b 4c 24 1c 02 d0 8b 44 24 10 32 14 01 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBU_2147763945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBU!MTB"
        threat_id = "2147763945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 0f b6 14 38 8a 1f 03 55 fc 0f b6 c3 03 c2 33 d2 f7 f1 8d 04 32 89 55 fc 8a 10 88 18 88 17 47 ff 4d f4 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 32 0f b6 c0 03 c2 33 d2 f7 f1 8b da 03 5d f0 ff 15 ?? ?? ?? ?? 8a 04 33 02 45 0f 8b 4d ec 32 04 39 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBV_2147763946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBV!MTB"
        threat_id = "2147763946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 1a 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 83 c3 01 83 6c 24 14 01 8b fa 8a 14 37 88 04 37 88 53 ff 89 7c 24 10 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 8b da 03 5c 24 20 ff 15 ?? ?? ?? ?? 8a 0c 33 8b 44 24 14 02 4c 24 28 8b 54 24 1c 32 0c 02 83 c0 01 83 6c 24 10 01 88 48 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBW_2147764110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBW!MTB"
        threat_id = "2147764110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 8b 55 f4 03 55 f0 0f b6 0a 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 45 1c 0f af 45 1c 03 d0 89 55 e4 8b 4d 08 03 4d ec 0f b6 11 8b 45 f4 03 45 e4 0f b6 08 8b 45 1c 0f af 45 1c 03 c8 33 d1 8b 4d 18 03 4d ec 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBX_2147764124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBX!MTB"
        threat_id = "2147764124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 37 8a 04 2e 02 c1 02 ca 88 44 24 2c 88 0c 2e 8b 4c 24 2c 88 04 37 33 c0 81 e1 ff 00 00 00 8a 04 2e 33 d2 03 c1 f7 35 ?? ?? ?? ?? 8b 44 24 3c 8b da 03 d8 ff 15 ?? ?? ?? ?? 8a 14 33 8a 44 24 2c 8b 4c 24 20 02 d0 8b 44 24 28 32 14 01 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_B_2147764178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.B!MTB"
        threat_id = "2147764178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 2e 8a 04 37 88 14 37 88 04 2e 0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 1c ff 15 ?? ?? ?? ?? 8b 44 24 18 8a 0c 18 8b 54 24 14 32 0c 32 83 c3 01 83 6c 24 24 01 88 4b ff 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 f6 8b fa 8a 14 29 8a 04 0f 02 c3 02 d3 88 14 0f 88 04 29 0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8b 74 24 24 46 89 74 24 24 03 54 24 18 0f b6 04 0a 8b 54 24 10 02 c3 32 44 32 ff ff 4c 24 14 88 46 ff 75}  //weight: 1, accuracy: High
        $x_1_3 = {89 54 24 20 ff d5 6a 00 6a 00 ff d5 6a 00 6a 00 ff d5 6a 00 6a 00 ff d5 8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 31 40 88 50 ff 89 44 24 24 ff 4c 24 10 75 8c 5f 5e 5d 5b 83 c4 0c c3}  //weight: 1, accuracy: High
        $x_1_4 = {ff d5 6a 00 6a 00 ff d5 6a 00 6a 00 ff d5 8b 4c 24 2c 8b 44 24 28 8a 14 01 8b 4c 24 1c 32 14 31 40 89 44 24 28 88 50 ff 8b 44 24 24 48 89 44 24 24 0f 85 ?? ff ff ff 5f 5e 5d 5b 83 c4 08 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 04 3b 0f b6 ca 03 c1 33 d2 f7 f5 8b ea ff d6 ff d6 ff d6 ff d6 ff d6 ff d6 ff d6 ff d6 8b 44 24 24 8b 54 24 18 8a 0c 02 32 0c 2f 40 83 6c 24 14 01 88 48 ff 89 44 24 24 75}  //weight: 1, accuracy: High
        $x_1_6 = {88 14 0f 88 04 0e 0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 35 ?? ?? ?? ?? 03 54 24 14 8a 04 0a 8b 54 24 18 02 c3 32 04 2a 45 88 45 ff 8b 44 24 10 48 89 6c 24 24 89 44 24 10 75}  //weight: 1, accuracy: Low
        $x_1_7 = {33 d2 f7 f1 8a 0c 33 02 4d ff 8a 04 32 02 45 ff 88 0c 32 88 04 33 8b ca 0f b6 0c 31 0f b6 c0 03 c1 89 55 f8 33 d2 f7 35 ?? ?? ?? ?? 8b 4d f4 03 55 f0 8a 04 32 02 45 ff 32 04 39 88 07 47 ff 4d 0c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBY_2147764204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBY!MTB"
        threat_id = "2147764204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 12 0f b6 c0 03 c2 33 d2 f7 f1 89 55 ec ff 15 ?? ?? ?? ?? 8b 45 f4 8a 04 38 8b 4d ec 32 04 31 88 07}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 1c ff 15 ?? ?? ?? ?? 8b 44 24 18 8a 0c 18 8b 54 24 14 32 0c 32 83 c3 01 83 6c 24 24 01 88 4b ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PBZ_2147764210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PBZ!MTB"
        threat_id = "2147764210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 55 17 02 14 33 88 10 88 0c 33 0f b6 00 0f b6 c9 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 4d 1c 03 55 10 8a 04 32 02 45 17 32 04 39 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCA_2147764254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCA!MTB"
        threat_id = "2147764254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 37 8b da 8a 04 33 88 0c 33 88 04 37 0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 1c ff 15 ?? ?? ?? ?? 8b 44 24 10 8a 0c 28 8b 54 24 14 32 0c 32 8b 44 24 20 88 4d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCB_2147764255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCB!MTB"
        threat_id = "2147764255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 0f 02 c3 02 d3 88 14 0f 88 04 29 0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8b 74 24 24 46 89 74 24 24 03 54 24 18 0f b6 04 0a 8b 54 24 10 02 c3 32 44 32 ff 83 6c 24 14 01 88 46 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCC_2147764256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCC!MTB"
        threat_id = "2147764256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 1c 0f af 45 1c 03 d0 89 55 ec 8b 4d 08 03 4d e4 0f b6 11 8b 45 f4 03 45 ec 0f b6 08 8b 45 1c 0f af 45 1c 03 c8 33 d1 8b 4d 18 03 4d e4 88 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCD_2147764430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCD!MTB"
        threat_id = "2147764430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 33 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 34 ff 15 ?? ?? ?? ?? 8b 44 24 24 8b 54 24 2c 8a 0c 28 8a 04 32 32 c8 8b 44 24 20 88 4d 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 0c 1a 33 d2 03 c1 f7 f7 8b f2 ff 15 ?? ?? ?? ?? 8b 4d 18 8b 55 08 0f b6 04 0a 32 04 1e 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCE_2147764440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCE!MTB"
        threat_id = "2147764440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c1 8b cf 33 d2 0f b6 0c 19 03 c1 f7 35 ?? ?? ?? ?? 8b 4c 24 20 03 54 24 18 0f b6 04 1a 02 44 24 24 32 44 31 ff 88 46 ff}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 18 ff d3}  //weight: 1, accuracy: High
        $x_1_3 = {ff d3 8b 44 24 24 8b 4c 24 18 0f b6 14 01 8b 4c 24 10 32 14 31 83 c0 01 83 6c 24 14 01 88 50 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_PCF_2147764490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCF!MTB"
        threat_id = "2147764490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 1c ff 15 ?? ?? ?? ?? 8b 44 24 18 8a 0c 18 8b 54 24 14 32 0c 32 43 83 6c 24 24 01 88 4b ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 00 0f b6 d2 03 c2 33 d2 f7 f1 89 55 14 ff 15 ?? ?? ?? ?? 8b 45 0c 8b 4d 14 8a 04 38 32 04 31 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCG_2147764600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCG!MTB"
        threat_id = "2147764600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 33 0f b6 c0 03 c1 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 44 24 14 8b 4c 24 1c 83 c0 01 89 44 24 14 0f b6 14 32 32 54 01 ff 83 6c 24 18 01 88 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8a 04 0a 8b 54 24 18 32 04 1a 43 88 43 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCH_2147764695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCH!MTB"
        threat_id = "2147764695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 0e 0f b6 c0 03 c2 33 d2 f7 f5 0f b6 04 0a 8b 54 24 14 32 44 1a ff 83 6c 24 20 01 88 43 ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 14 ff 15 ?? ?? ?? ?? 8b 44 24 10 8a 0c 28 8b 54 24 14 32 0c 32 8b 44 24 20 88 4d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 12 0f b6 c0 03 c2 33 d2 f7 f1 8b da ff 15 ?? ?? ?? ?? 8b 45 f4 8a 04 38 32 04 33 88 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_AR_2147764750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AR!MTB"
        threat_id = "2147764750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\DODO\\Videos\\win32_memdc_src\\Release\\Win32_MemDC.pdb" ascii //weight: 1
        $x_1_2 = "CSBhvSWCvFRvfCfAoJdoFuAUmK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_AR_2147764750_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AR!MTB"
        threat_id = "2147764750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2b 8a 03 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 03 47 43 8a 0c 32 88 04 32 88 4b ff 8b 0d ?? ?? ?? ?? 3b f9 89 54 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 10 8b 4c 24 18 8a 14 01 8b 4c 24 1c 32 14 31 40 88 50 ff 89 44 24 10 ff 4c 24 14}  //weight: 1, accuracy: High
        $x_1_3 = "L9gfefdTTRvh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_AR_2147764750_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AR!MTB"
        threat_id = "2147764750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 14 8d 2c 3b 88 1c 28 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 3b de 8a 14 02 88 55 00}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 f7 f6 8a 03 43 8b fa 8a 14 0f 88 04 0f 8b 44 24 14 88 53 ff 48 89 7c 24 10 89 44 24 14}  //weight: 1, accuracy: High
        $x_2_3 = {88 14 0f 88 04 29 0f b6 14 29 0f b6 04 0f 03 c2 33 d2 f7 f6 8a 04 0a 8b 54 24 18 32 04 1a 43 88 43 ff ff 4c 24 14}  //weight: 2, accuracy: High
        $x_1_4 = "B56wrg7Qrxtth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_AR_2147764750_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AR!MTB"
        threat_id = "2147764750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 99 f7 7c 24 2c 8b 44 24 28 8d 0c 2b 88 1c 0e 43 8a 14 02 88 11 8b 0d ?? ?? ?? ?? 3b d9 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 2e 8a 06 03 54 24 10 0f b6 c0 03 c2 33 d2 f7 f1 8a 06 43 46 8a 0c 3a 88 04 3a 88 4e ff 8b 0d ?? ?? ?? ?? 3b d9 89 54 24 10 72}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 24 8b 4c 24 14 8a 14 01 8b 4c 24 18 32 14 39 40 88 50 ff 89 44 24 24 ff 4c 24 10 75}  //weight: 1, accuracy: High
        $x_3_4 = "Qyinyhjjbt67" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_AR_2147764750_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AR!MTB"
        threat_id = "2147764750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 24 20 88 14 0f 88 04 0e 0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 54 24 14 32 04 1a 43 88 43 ff ff 4c 24 10}  //weight: 2, accuracy: Low
        $x_1_2 = "y6ithgrhhytt" ascii //weight: 1
        $x_1_3 = "c:\\Users\\Dodo\\Downloads\\WebPageSnapShot\\Release\\WebPageSnapShot.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_AR_2147764750_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AR!MTB"
        threat_id = "2147764750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8d 34 3b 88 1c 30 8b c3 99 f7 7c 24 2c 8b 44 24 28 43 8a 14 02 88 16 8b 2d ?? ?? ?? ?? 3b dd}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 14 1f 03 54 24 10 8a 03 0f b6 c0 03 c2 33 d2 f7 f5 8a 03 46 43 8b ea 8a 14 29 88 04 29 88 53 ff 89 6c 24 10}  //weight: 1, accuracy: High
        $x_1_3 = {03 54 24 14 8a 04 0a 8b 54 24 18 02 c3 32 04 2a 45 88 45 ff 8b 44 24 10 48 89 6c 24 24 89 44 24 10}  //weight: 1, accuracy: High
        $x_1_4 = "drtffDWEUFEUFUWEGFUYBG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCI_2147764815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCI!MTB"
        threat_id = "2147764815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 54 24 14 32 04 1a 43 88 43 ff}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b6 04 3b 0f b6 ca 03 c1 33 d2 f7 f5 8b ea}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 24 8b 54 24 18 8a 0c 02 32 0c 2f 83 c0 01 83 6c 24 14 01 88 48 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_PCK_2147764832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCK!MTB"
        threat_id = "2147764832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 32 33 d2 0f b6 c9 03 c1 b9 ?? ?? ?? ?? f7 f1 8b 4d 18 2b 15 ?? ?? ?? ?? 03 d7 8a 04 32 8b 55 f8 02 c2 8b 55 08 32 04 0a 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCL_2147764837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCL!MTB"
        threat_id = "2147764837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 33 0f b6 c0 03 c2 33 d2 f7 f1 89 54 24 10 [0-20] 8b 44 24 24 8b 4c 24 18 0f b6 14 01 8b 4c 24 10 32 14 31 83 c0 01 83 6c 24 14 01 88 50 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_ARK_2147764873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.ARK!MTB"
        threat_id = "2147764873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8b 2d ?? ?? ?? ?? 8b fa 0f b6 04 37 03 c3 33 d2 f7 f1 8a 0c 37 8b da 8a 04 33 88 0c 33 88 04 37 0f b6 14 33}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8b 4d f8 8b 15 ?? ?? ?? ?? 03 c1 0f b6 4d ff 8a 0c 11 30 08 ff 45 f8 8b 45 f8 3b 45 0c 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 13 03 c2 99 b9 e3 03 00 00 f7 f9 a1 ?? ?? ?? ?? 45 0f b6 d2 8a 0c 02 30 4d ff 83 6c 24 14 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_ARK_2147764873_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.ARK!MTB"
        threat_id = "2147764873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 8b 44 24 14 8b 74 24 1c 30 0c 30 40 3b 44 24 20 89 44 24 14 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = {8a 14 0a 03 c6 30 10 46 3b 75 0c 89 74 24 14 0f 8c}  //weight: 1, accuracy: High
        $x_1_3 = {8a 0c 11 30 08 ff 44 24 14 8b 44 24 14 3b 44 24 24 0f 8c ?? ?? ?? ?? 8b 44 24 28 8a 4c 24 12 8a 54 24 13 5f 5e 5d 5b 88 08}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4c 24 44 8b 44 24 4c 8b 15 ?? ?? ?? ?? 03 c1 0f b6 4c 24 41 8a 0c 11 30 08 83 c4 30 ff 44 24 14 8b 44 24 14 3b 44 24 20 0f 8c 3c ff ff ff}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 44 0b ff 03 d5 03 c2 99 bd f3 02 00 00 f7 fd 0f b6 ea 8a 54 0b ff 8d 04 2b 88 54 24 20 8a 10 88 54 0b ff 8a 54 24 20 88 10 8b 44 24 10 40 99 f7 fe 81 f9 f3 02 00 00 0f}  //weight: 1, accuracy: High
        $x_1_6 = {8a 14 11 8b 44 24 14 8b 4c 24 1c 30 14 08 8b 4c 24 20 40 3b c1 89 44 24 14 0f}  //weight: 1, accuracy: High
        $x_1_7 = {8a 0c 02 8b 44 24 20 8a 14 03 32 d1 88 14 03 8b 44 24 24 43 3b d8 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_ARK_2147764873_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.ARK!MTB"
        threat_id = "2147764873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 08 32 14 2e 8b 4c 24 2c 88 14 08 [0-31] 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 83 ee fc 83 e8 33 c1 c8 08 29 d8 83 e8 01 8d 18 c1 c3 09 d1 cb 6a 00 8f 02 01 02}  //weight: 1, accuracy: High
        $x_1_3 = {81 e1 ff 00 00 00 03 c1 b9 7b 04 00 00 99 f7 f9 8a 03 83 c4 0c 8a 54 14 14 32 c2 88 03 43 4d}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 94 14 00 30 55 ff [0-79] 0f 85}  //weight: 1, accuracy: Low
        $x_1_5 = {99 f7 f9 8a 03 [0-63] 8a 94 14 ?? ?? ?? ?? 32 c2 88 03 8f 00 8a 84 34 01 81 e1 [0-4] 03 c1 b9}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 14 [0-5] c7 84 24 ?? ?? ?? ?? ff ff ff ff 0f b6 94 14 00 30 55 ff}  //weight: 1, accuracy: Low
        $x_1_7 = {33 d2 8a 94 0d ?? ?? ?? ?? 03 c2 99 f7 bd ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 32 84 15 00 88 85 02 8b 4d 10 03 8d ?? ?? ?? ?? 8a 95 02 88 11 8b 85 05 83 c0 01 89 85 05 e9}  //weight: 1, accuracy: Low
        $x_1_8 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 c9 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 18 8a 9c 14 00 32 5d 00 [0-31] 88 5d 00}  //weight: 1, accuracy: Low
        $x_1_9 = {33 d2 8a 54 04 [0-4] 8b c2 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 5c 14 00 8b 54 24 1c 32 1a}  //weight: 1, accuracy: Low
        $x_1_10 = {0f b6 01 0f b6 ca 03 c1 99 8b cb f7 f9 8b 4d e8 33 db 53 53 8a 44 15 00 32 01}  //weight: 1, accuracy: High
        $x_1_11 = {08 0f b6 44 2c 2c 0f b6 c9 03 c1 99 8b cb f7 f9 8b 44 24 20 8a 5c 14 2c 8b 54 24 24 32 1c 02}  //weight: 1, accuracy: High
        $x_1_12 = {8a 44 0c 34 b9 ?? ?? ?? ?? 03 c2 99 f7 f9 8a 4c 24 17 [0-5] 8a 54 14 34 32 ca}  //weight: 1, accuracy: Low
        $x_1_13 = {03 c1 99 b9 57 2b 01 00 f7 f9 8a 5c 24 13 8b 44 24 14 8a 54 14 18 32 d3 88 55 00}  //weight: 1, accuracy: High
        $x_1_14 = {8a 04 0e 81 e2 ff 00 00 00 03 c2 99 f7 fd 8a 04 0a 8b 54 24 18 32 04 1a}  //weight: 1, accuracy: High
        $x_1_15 = {81 e1 ff 00 00 00 [0-15] 8a 84 14 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 4c 24 13 8b 84 24 ?? ?? ?? ?? 8a 94 14 01 32 ca}  //weight: 1, accuracy: Low
        $x_1_16 = {0f b6 cb 03 c1 99 b9 57 2b 01 00 f7 f9 83 c5 01 0f b6 54 14 18 32 54 24 13 83 bc 24 84 2b 01 00 00 88 55 ff 75 92}  //weight: 1, accuracy: High
        $x_1_17 = {8b 4c 24 1c 0f b6 44 0c [0-4] 0f b6 d3 03 c2 99 b9 4a 2f 01 00 f7 f9 8a 5c 24 1b 32 5c 14 00}  //weight: 1, accuracy: Low
        $x_1_18 = {0f b6 44 04 28 0f b6 cb 03 c1 99 b9 4a 2f 01 00 f7 f9 8a 5c 24 17 32 5c 14 28}  //weight: 1, accuracy: High
        $x_1_19 = {0f b6 44 0c [0-4] 0f b6 d3 03 c2 99 b9 ?? ?? ?? ?? f7 f9 8a 5c 24 1b 32 5c 14 00 3b fe 0f}  //weight: 1, accuracy: Low
        $x_1_20 = {32 14 01 83 c0 01 83 6c 24 14 01 88 50 ff 89 44 24 10 0f 85 24 ff ff ff}  //weight: 1, accuracy: High
        $x_1_21 = {41 8a 8c 0d 8c 00 00 00 8b 55 80 32 0c 3a 88 0f 47 [0-31] 75}  //weight: 1, accuracy: Low
        $x_1_22 = {8a 54 14 14 8a 1c 0f 32 d3 88 11 41 4d 75 94}  //weight: 1, accuracy: High
        $x_1_23 = {0f b6 00 0f b6 d2 03 c2 99 f7 fb 8a 04 0a 8b 55 0c 32 04 3a 88 07}  //weight: 1, accuracy: High
        $x_1_24 = {8a 14 01 8b 4c 24 1c 32 54 0c 20 40 88 50 ff [0-31] 0f}  //weight: 1, accuracy: Low
        $x_1_25 = {8a 0c 02 8b 54 24 1c 32 4c 14 20 83 c0 01 [0-31] 0f 85}  //weight: 1, accuracy: Low
        $x_1_26 = {8a 14 2e 32 c2 88 06 46 4b 75 a4 4f 00 8a 44 3c ?? 81 [0-31] f7 [0-15] 8a 44 14 01}  //weight: 1, accuracy: Low
        $x_1_27 = {0f b6 04 0f 0f b6 d2 03 c2 33 d2 f7 35 50 b1 49 00 8a 04 0a 32 04 2b 88 45 00}  //weight: 1, accuracy: High
        $x_1_28 = {8b 00 8b ea 8b 54 24 1c 8a 14 10 32 14 2e 8b 6c 24 2c 88 14 28 [0-31] 72}  //weight: 1, accuracy: Low
        $x_1_29 = {8a 04 17 8a 14 2e 32 c2 8b 54 24 2c 88 04 17 [0-15] 40 [0-15] 72}  //weight: 1, accuracy: Low
        $x_1_30 = {0f b6 d2 03 c2 99 f7 fb 8a 1c 29 8a 44 14 14 32 c3 88 01}  //weight: 1, accuracy: High
        $x_1_31 = {8b 00 8b fa 8b 54 24 1c 8a 14 10 32 14 37 88 14 18}  //weight: 1, accuracy: High
        $x_1_32 = {0f b6 8c 15 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 8d ?? ?? ?? ?? 0f b6 84 15 00 32 44 1f ff ff 4d 0c 88 43 ff 75}  //weight: 1, accuracy: Low
        $x_1_33 = {8a 1c 06 2a 1d ?? ?? ?? ?? 2a d9 02 da 88 18 40 4f 75 ?? 5e 5b 5f c3}  //weight: 1, accuracy: Low
        $x_1_34 = {33 d2 f7 35 ?? ?? ?? ?? 8a 04 0a 8b 54 24 28 32 04 2a 45 88 45 ff 8b 44 24 [0-4] 48 89 44 24 01 75}  //weight: 1, accuracy: Low
        $x_1_35 = {0f b6 00 0f b6 d2 03 c2 33 d2 f7 f1 8b 4d f8 8a 04 32 32 04 39 88 07}  //weight: 1, accuracy: High
        $x_1_36 = {88 04 33 0f b6 09 0f b6 c0 03 c1 33 d2 f7 35 ?? ?? ?? ?? 8b 4d f4 8a 04 32 32 04 39 88 07}  //weight: 1, accuracy: Low
        $x_1_37 = {8a 14 33 8a 44 24 2c 8b 4c 24 20 02 d0 8b 44 24 28 32 14 01 88 10}  //weight: 1, accuracy: High
        $x_1_38 = {8a 14 3a 02 d0 8b 44 24 24 32 14 01 40 89 44 24 24 88 50 ff}  //weight: 1, accuracy: High
        $x_1_39 = {0f b6 04 0a 8b 54 24 10 02 c3 32 44 32 ff ff 4c 24 14 88 46 ff 75}  //weight: 1, accuracy: High
        $x_1_40 = {8a 04 0a 8b 54 24 14 32 04 2a 45 88 45 ff ff 4c 24 20 75}  //weight: 1, accuracy: High
        $x_1_41 = {0f b6 0c 0a [0-15] 33 d2 f7 35 34 60 41 00 [0-47] 0f b6 09 33 c1 8b 4d 18 03 4d dc 88 01}  //weight: 1, accuracy: Low
        $x_1_42 = {8a 14 08 8b 44 24 18 30 14 28 [0-15] 45 3b e8 0f 8c 70}  //weight: 1, accuracy: Low
        $x_1_43 = {8a 14 0a 03 c6 30 10 46 3b 75 0c 89 74 24 14 7c}  //weight: 1, accuracy: High
        $x_1_44 = {8a 14 02 8b 44 24 14 8b 4c 24 1c 30 14 08 40 3b 44 24 20 89 44 24 14 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_ARK_2147764873_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.ARK!MTB"
        threat_id = "2147764873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f7 8b fa 8a 94 3d ?? ?? ?? ?? 88 11 8d 84 3d 00 88 18 8b 45 fc 40 3d ?? ?? ?? ?? 89 45 fc 72 8f 00 8d 8c 05 00 f7 75 0c [0-10] 0f b6 14 02 0f b6 c3 03 fa 33 d2 03 c7 bf 02}  //weight: 5, accuracy: Low
        $x_2_2 = {83 c2 01 89 95 ?? ?? ?? ?? 8b 85 00 3b 85 ?? ?? ?? ?? 73 ?? eb 6f 00 c7 85 02 ?? ?? ?? ?? c7 85 00 00 00 00 00 eb [0-5] 8b 85 00 8a 8d 00 88 8c 05 [0-5] 8b 95 00}  //weight: 2, accuracy: Low
        $x_3_3 = {03 c2 99 f7 bd ?? ?? ?? ?? 8a 85 ?? ?? ?? ?? 32 84 15 ?? ?? ?? ?? 4f 00 8a 94 0d 02}  //weight: 3, accuracy: Low
        $x_4_4 = "iro0h3ZuIA#jQ!&7cHqAx#!%U4CKgejKgrzy" ascii //weight: 4
        $x_1_5 = "CZ5gi3jH" ascii //weight: 1
        $x_4_6 = "wROsSM9vlw3BblCN13DrELqT3GPPEdQlQ8PMaB" ascii //weight: 4
        $x_4_7 = "7SDSiS6HD09PtruOuni0p2w6wW8vyCv7Xiz" ascii //weight: 4
        $x_5_8 = "Si4rPgXBWi9XXfDZTdcN4qcNnxbhNSaVCJoi4" ascii //weight: 5
        $x_5_9 = "evaG4R104NUYbvb2u36agAPr51rHWuglj0ZVT" ascii //weight: 5
        $x_5_10 = "sfR1rITOyR43NeiuF25jmw5PIN4fTMQLVQLdAkb" ascii //weight: 5
        $x_5_11 = "I9##10e{h}AR20N2{hAqB}X$htYVj~sq|6L7DHdx|Mk5$bsL$ThK7pX4%HCaV|o#lZLVlN}0Sq~z{Xz" ascii //weight: 5
        $x_5_12 = "1c9dLOCk~cXP06GB3zHouOK}yF{EwLinUs$20mm33C7JdkgCMFnmwldWgoqWPPeoUSI?~7SqYht" ascii //weight: 5
        $x_5_13 = "knY5mY86~b{@py}FYNZWNR2ysYe3npe*g*AX05pO7qs4~NGf0?B4?YWPH$}yp~dpjS" ascii //weight: 5
        $x_5_14 = "ELNU%CFqK2Sf8wxYYjXb{BZUtBdv~OuTMdCygKXi40YPJ@*AjN*x9" ascii //weight: 5
        $x_5_15 = "0WmfLjNQIqUtwtvadlxNXC?y~xbeK~$uLkOQa%?~Wj4a3#Lu" ascii //weight: 5
        $x_5_16 = "dlxNXC?y~xbeK~$uLkOQa%?~Wj4a3#Lu" ascii //weight: 5
        $x_5_17 = "TklQ6Zr%7Pb$7r*0rHpUhAexjID4j4QC2kjIF{GdR2HB2l8JgiMN%bm54jiSd*U$MOwN@Zrn1u9@G$VZLtkehuu" ascii //weight: 5
        $x_5_18 = "D}Y${ElPDqgV58%bKT94%GJPOQE9CnAuhSzncHpFvufD4%jrQdI08o0At6i$N?aLDAaN$" ascii //weight: 5
        $x_5_19 = "9zVar6dkpD|8mRFc%X*zZV5BSFXbmNh2k#APquPp*4TD0eI{N2?Q6i#?}1SCwmXxfbB#N4H6nD" ascii //weight: 5
        $x_5_20 = "5$%zMx~KSOi?g~$wLhCy7M0QE2MaQ*DBW?r9Dn?u%NwGA#mSh7oXMS||%*SkTy#g{BCSrMx?ZqzU" ascii //weight: 5
        $x_5_21 = "NI9PJ6bfPYzbG9DHlpNc2ajvYITUHsfdFP0IngPNWq1yta4EAO40FuvJ3" ascii //weight: 5
        $x_4_22 = "uyfhhrt78ueghsdjfkgadhfjwgdfreuDSArtD" ascii //weight: 4
        $x_5_23 = "lWnj!py7NUA&n4D4@wzbon@lB%QiMm0JAm!enM" ascii //weight: 5
        $x_5_24 = "l%w79M_n*GPju_D8Tu>LorvmYCWkpYhx6ZF@&gG4ahp**dtWp4MQCUVmhR!REg7muw$xmxIm)jbtT+bcGbrnnnO*W#rOV7Mbbf^vF" ascii //weight: 5
        $x_5_25 = "x21aqeSNAQVInK^j8AHT&FFoNnLkWCy75KYxr+WdH(xb0O&CP)1$aHZ!c3xjoGz(G5RieG&qw9NBt#k4@>fk8wHOq&V#%B%fP5pD6S" ascii //weight: 5
        $x_5_26 = "H@ozyogq9h2WPa5oo83b>xTDzHtEUarrVsT6C&A23VD$V+ZBtrRP8Iud&uRu4Jy)q_bva0I+ixZu(er4U*E#$%51musR9de&9NW$ND^U5W" ascii //weight: 5
        $x_5_27 = "S*R7DB2(DHQX9WCcjGX>zlYU@ePKDMen2f(qKOZn_&Yo@v>ffT!6m$Uq@06^vNc9h5fUNnsyhIxk)5DI>&ZZ<wXiBeQ@Xe&TpT%1Hs2X!JJt&j" ascii //weight: 5
        $x_4_28 = "KM4LS1H<*Vr2Wcpsb6D<ri(tLky5akyXgWyI$6" ascii //weight: 4
        $x_1_29 = "SDASQFddefgshdSSSgfdtEghfIITFDSSSSS+3EE" ascii //weight: 1
        $x_5_30 = "6rBHpj)3jwOUAiBct(l4^sp_8Hb+0R7SfP1hMZ>uFswJZh" ascii //weight: 5
        $x_5_31 = "rozLpiq>Xes6gJ@2p5p4pR!eAcz9t*SrT>g9pNDaj^R" ascii //weight: 5
        $x_5_32 = "0AZkvpRg?$1qGee+V(IyT5+(BXtWsK5T(CMwBn7TH4n49u>QPvtHXFR9W0#SyT3a)axz?*>A7ipIoJi%jBQgvhp*@6k9phaI_>U1Q25hJKCX+IXbo@" ascii //weight: 5
        $x_5_33 = "5m3tSe$>wy_L(k?2ACzqZb5Qe(T*SupJH3L%@DqYpO@&HW41mZ<?XN>P>swKv2uS%UicysERpXwM" ascii //weight: 5
        $x_5_34 = "9<s0RyiTN#4_nW5wJkRt@BG2?#vg)!ZEBrHS#j?j4iIxTS<QL4)<" ascii //weight: 5
        $x_5_35 = "v0Tf#!EanqMuM044t6sghaowV5v0&@OLCY+seOh7meJE3eWjPRAj+FzJA+j3+N&RK*#f0mvhljm(" ascii //weight: 5
        $x_5_36 = "*RqDG03aZ@!6XDocl<Z!9JXG_+<v$7^VvyL)qxeYpGuAspu?O)<k#laDC0t)UEtW69_N#?RYHL*yaj5M$<1T)?FYTR6b(*^YAlOQudANs" ascii //weight: 5
        $x_5_37 = "F$!wJX5_rq<T(QsJO+xeB9KA3YFC_ErfIjvsZ" ascii //weight: 5
        $x_5_38 = "RWUuW5gS@hfwK)yb1mgCYBZU&nRIWTAiznp*#&Y?TjJh?zyRUJgTv#^I<_$xfQ)sN" ascii //weight: 5
        $x_5_39 = "!mTQ7g!t?ztgKrKK$%>HYFN0fX_x^dq&2qYUJ<(qvk$u+08UI70GYbt?gso*MplqMhA5TWdv*tt+5r" ascii //weight: 5
        $x_5_40 = "dL@?R)$Rw>M^63qJ2lMP42YLe42nYjVahmJcR9MCyY_F&Osz&H&^ghQ*>8mG" ascii //weight: 5
        $x_5_41 = "*FLrY4bO%4Th$J8Gt0z*zKiB)Yb#mGNysUj<>gI0J>xxnPNXTre@<I8bJw1MjL6q8sG7ry9^Ck)r)6Da+ol9@K" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_PCM_2147764898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCM!MTB"
        threat_id = "2147764898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 10 88 18 8b 5d f8 88 14 33 0f b6 00 0f b6 d2 03 c2 33 d2 f7 f1 8b 4d f0 8a 04 32 32 04 39 88 07}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 0c 0a 03 c1 33 d2 f7 35 ?? ?? ?? ?? 89 55 e4 8b 45 08 03 45 dc 0f b6 00 8b 4d f0 03 4d e4 0f b6 09 33 c1 8b 4d 18 03 4d dc 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCN_2147764899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCN!MTB"
        threat_id = "2147764899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 29 0f b6 04 0f 03 c2 33 d2 f7 f6 8a 04 0a 8b 54 24 18 32 04 1a 43 88 43 ff}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 04 33 03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 54 24 20 ff 15 ?? ?? ?? ?? 8b 44 24 14 8a 0c 28 8b 54 24 20 32 0c 32 8b 44 24 10 88 4d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_RK_2147764977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.RK!MTB"
        threat_id = "2147764977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Char2ActivateTranNextChar2Upper" ascii //weight: 1
        $x_1_2 = {3a 00 00 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "AUTONEXTFLEXINPUT(" wide //weight: 1
        $x_1_4 = {01 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_5_5 = {bb 01 00 00 00 33 ff b9 df 25 01 00 50 3b f9 7f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_RK_2147764977_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.RK!MTB"
        threat_id = "2147764977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "useradvancededit" wide //weight: 1
        $x_1_2 = "K*\\AD:\\karaoke\\Karaoke2.vbp" wide //weight: 1
        $x_1_3 = "Browse for kar files" wide //weight: 1
        $x_1_4 = "NHs2NHsDNHsXNHsjNHs~NHs" ascii //weight: 1
        $x_1_5 = "OHs(OHs<OHsNOHsbOHstOHs" ascii //weight: 1
        $x_1_6 = "PHs PHs2PHsFPHsXPHslPHs~PHs" ascii //weight: 1
        $x_1_7 = "QHs*QHs<QHsPQHsbQHsvQHs" ascii //weight: 1
        $x_1_8 = "RHs RHs4RHsFRHsZRHslRHs" ascii //weight: 1
        $x_1_9 = "SHs*SHs>SHsPSHsdSHsvSHs" ascii //weight: 1
        $x_1_10 = "THs\"THs4THsHTHsZTHsnTHs" ascii //weight: 1
        $x_1_11 = "UHs,UHs>UHsRUHsdUHsxUHs" ascii //weight: 1
        $x_5_12 = {3a 00 00 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PA_2147765194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PA!MTB"
        threat_id = "2147765194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 61 03 00 00 f7 f9 8b 0d ?? ?? ?? ?? bf 61 03 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 0f b6 f2 0f b6 04 0e 03 c5 88 54 24 ?? 99}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 00 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 8b 44 24 ?? 8b 3d ?? ?? ?? ?? 8b d1 2b 15 ?? ?? ?? ?? 83 c1 01 03 c2 0f b6 54 24 ?? 8a 14 3a 30 10 3b 4c 24 ?? 89 4c 24 ?? 0f 8c ?? ?? ?? ?? 8a 4c 24 ?? 8b 44 24 ?? 8a 54 24 ?? 5f 5e 5d 5b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCO_2147765195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCO!MTB"
        threat_id = "2147765195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 20 8a 0c 32 8b 44 24 10 02 4c 24 30 8b 54 24 24 32 0c 02 83 c0 01 83 6c 24 18 01 88 48 ff 89 44 24 10 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 0f 0f b6 c0 03 c2 33 d2 f7 f6 8b 74 24 ?? 83 c6 01 89 74 24 ?? 03 54 24 ?? 0f b6 04 0a 8b 54 24 ?? 02 c3 32 44 32 ff 83 6c 24 ?? 01 88 46 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCP_2147765196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCP!MTB"
        threat_id = "2147765196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Users\\DODO\\Videos\\TransparentControl_src\\TransparentControl\\Release\\TransparentControl.pdb" ascii //weight: 1
        $x_1_2 = "CSBhvSWCvFRvfCfAoJdoFuAUmK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCP_2147765196_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCP!MTB"
        threat_id = "2147765196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_11_1 = "7MzNf0lEMFdqDSN" ascii //weight: 11
        $x_9_2 = "3U6RsjVf0st0TJf.pdb" ascii //weight: 9
        $x_7_3 = "qsjwWIuTYdfvkTi" ascii //weight: 7
        $x_11_4 = "jZTnibSeafLGCHGT" ascii //weight: 11
        $x_9_5 = "nterDriv.uu.pdb" ascii //weight: 9
        $x_7_6 = "HWWetttEE" ascii //weight: 7
        $x_11_7 = "fThDTdqYBHT.cab" ascii //weight: 11
        $x_9_8 = "tNc6L75*9/z.pdb" ascii //weight: 9
        $x_7_9 = "a5JAQscnAG" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 3 of ($x_7_*))) or
            ((2 of ($x_9_*) and 2 of ($x_7_*))) or
            ((3 of ($x_9_*))) or
            ((1 of ($x_11_*) and 3 of ($x_7_*))) or
            ((1 of ($x_11_*) and 1 of ($x_9_*) and 1 of ($x_7_*))) or
            ((1 of ($x_11_*) and 2 of ($x_9_*))) or
            ((2 of ($x_11_*) and 1 of ($x_7_*))) or
            ((2 of ($x_11_*) and 1 of ($x_9_*))) or
            ((3 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_C_2147765309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.C!MTB"
        threat_id = "2147765309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 33 03 45 fc f7 f1 8a 45 17 02 04 33 89 55 fc 8b 5d fc 8a 14 32 02 55 17 88 04 33 8b 5d 10 8b 45 fc 88 14 33 0f b6 04 30 0f b6 d2 03 c2 33 d2 f7 f1 03 55 1c 8a 04 32 8b 55 08 02 45 17 32 04 3a 88 07 47 ff 4d 18 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 37 0f b6 c0 03 c2 33 d2 f7 f1 8b da 03 5c 24 18 ff 15 ?? ?? ?? ?? 8a 0c 33 8b 44 24 14 02 4c 24 28 8b 54 24 1c 32 0c 02 83 c0 01 83 6c 24 10 01 88 48 ff 89 44 24 14 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c3 8d 70 01 8a 10 40 84 d2 75 f9 2b c6 8b f8 8b 44 24 1c 8d 34 01 33 d2 8b c1 f7 f7 8a 04 2e 8a 14 1a 32 d0 8b 44 24 20 41 3b c8 88 16 75 d0 5f 5e 5d 5b c3}  //weight: 1, accuracy: High
        $x_1_4 = {0f b6 04 0f 0f b6 0c 0e 03 c1 99 b9 ?? ?? ?? ?? f7 f9 88 54 24 12 ff 15 ?? ?? ?? ?? 0f b6 54 24 12 a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 18 30 0c 28 45 3b 6c 24 1c 7c ?? 8b 44 24 20 8a 54 24 13 5f 5e 88 18 5b 88 50 01 5d 59 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c8 04 6a 00 50 e8 ?? ?? ?? ?? 0f b6 54 24 11 a1 ?? ?? ?? ?? 8a 14 02 8b 44 24 14 8b 4c 24 1c 30 14 08 40 3b 44 24 20 89 44 24 14 0f 8c ?? ff ff ff 8a 4c 24 12 8b 44 24 24 8a 54 24 13 5f 5e 5d 5b}  //weight: 1, accuracy: Low
        $x_1_6 = {83 c4 08 8b c8 e8 ?? ?? ?? ?? 0f b6 55 f7 a1 ?? ?? ?? ?? 0f b6 0c 10 8b 55 08 03 55 f8 0f b6 02 33 c1 8b 4d 08 03 4d f8 88 01 e9 ?? ?? ff ff 8b 55 10 8a 45 fe 88 02 8b 4d 10 8a 55 ff 88 51 01 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_7 = {0f b6 55 f7 a1 ?? ?? ?? ?? 0f b6 0c 10 8b 55 08 03 55 f8 0f b6 02 33 c1 8b 4d 08 03 4d f8 88 01 e9 ?? ?? ff ff 8b 55 10 8a 45 fe 88 02 8b 4d 10 8a 55 ff 88 51 01 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_8 = {ff d6 0f b6 55 ff 8b 45 08 8b 7d f8 8b 0d ?? ?? ?? ?? 03 c7 8a 14 0a 30 10 47 3b 7d 0c 89 7d f8 7c ?? 8a 4d fe 8b 45 10 8a 55 fd 5f 5e 5b 88 08 88 50 01 c9 c3}  //weight: 1, accuracy: Low
        $x_1_9 = {0f b6 4c 24 11 8b 15 ?? ?? ?? ?? 8a 14 11 8b 44 24 18 8b 4c 24 20 30 14 08 8b 4c 24 24 40 3b c1 89 44 24 18 0f 8c ?? ?? ff ff 8b 44 24 28 8a 4c 24 12 8a 54 24 13 5f 5d 5b 88 08 88 50 01 5e 83 c4 0c c3}  //weight: 1, accuracy: Low
        $x_1_10 = {8a 0c 1a 88 04 1a 8b 45 fc 02 cd 88 0c 18 0f b6 04 1a 0f b6 c9 03 c1 33 d2 b9 ?? ?? ?? ?? f7 f1 8b 4d 08 03 55 f4 0f b6 04 1a 02 45 0f 32 44 31 ff 8a 6d 0f 88 46 ff 4f 75 ?? 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_11 = {0f b6 54 24 12 a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 18 30 0c 28 8b 44 24 1c 45 3b e8 0f 8c ?? ff ff ff 8b 44 24 20 8a 54 24 13 5f 88 18 5b 5e 88 50 01 5d 59 c3}  //weight: 1, accuracy: Low
        $x_1_12 = {53 58 8d 70 01 8d 49 00 8a 10 83 c0 01 84 d2 75 f7 2b c6 50 5f 8b 44 24 1c 8d 34 01 33 d2 8b c1 f7 f7 83 c1 01 8a 14 1a 32 14 2e 3b 4c 24 20 88 16 75 cd 5f 5e 5d 5b c3}  //weight: 1, accuracy: High
        $x_1_13 = {f7 ff 8a 04 0e 0f b6 fa 88 54 24 13 8a 14 0f 88 14 0e 88 04 0f 0f b6 14 0f 0f b6 04 0e 03 c2 99 f7 fb 0f b6 c2 8a 14 08 8b 44 24 18 30 14 28 8b 44 24 1c 45 3b e8 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCQ_2147765435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCQ!MTB"
        threat_id = "2147765435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 32 33 d2 0f b6 c9 03 c1 8b 4d ?? f7 f7 2b 15 ?? ?? ?? ?? 03 55 ?? 8a 04 32 8b 55 ?? 02 c2 8b 55 ?? 32 04 0a 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 11 8b 45 ?? 03 45 e4 0f b6 08 8b 45 1c 0f af 45 1c 03 c8 33 d1 8b 4d ?? 03 4d ?? 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCR_2147765495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCR!MTB"
        threat_id = "2147765495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 30 f7 35 ?? ?? ?? ?? 8b da 03 d9 ff 15 ?? ?? ?? ?? 8a 14 33 8a 44 24 28 8b 4c 24 1c 02 d0 8b 44 24 24 32 14 01 88 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCS_2147765610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCS!MTB"
        threat_id = "2147765610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 33 d2 8b 5d ?? 0f b6 0c 33 03 c1 b9 ?? ?? ?? ?? f7 f1 8b 4d ?? 0f b6 04 32 8b 55 ?? 32 04 0a 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCT_2147765781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCT!MTB"
        threat_id = "2147765781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8a 0c 38 02 4d 0f 8b 45 f4 8b 55 e4 32 0c 02 88 08 40 ff 4d f0 89 45 f4 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 14 29 0f b6 04 2e 03 c2 99 bb ?? ?? ?? ?? f7 fb 0f b6 c2 8a 14 28 8b 44 24 ?? 30 14 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCU_2147765875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCU!MTB"
        threat_id = "2147765875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 0e 0f b6 04 0f 03 c2 99 bb ?? ?? ?? ?? f7 fb 45 0f b6 c2 8a 0c 08 8b 44 24 ?? 30 4c 28 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_SS_2147765943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.SS!MTB"
        threat_id = "2147765943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c1 0f b6 4c 24 11 8a 0c 11 30 08 ff 44 24 14 8b 44 24 14 3b 44 24 20 0f 8c a3 fb ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCV_2147765963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCV!MTB"
        threat_id = "2147765963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 0e 0f b6 04 0f 03 c2 99 b9 ?? ?? ?? ?? f7 f9 88 54 24 ?? ff 15 ?? ?? ?? ?? 0f b6 54 24 ?? a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 ?? 30 0c 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCW_2147766013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCW!MTB"
        threat_id = "2147766013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 29 0f b6 0c 0f 03 c1 99 b9 ?? ?? ?? ?? f7 f9 88 54 24 11 [0-12] 0f b6 54 24 11 a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 ?? 30 0c 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_RA_2147766394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.RA!MTB"
        threat_id = "2147766394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 11 03 c2 8b 4d ?? 81 e1 ff 00 00 00 03 c1 99 b9 ?? ?? ?? ?? f7 f9 88 55 00 8b 55 00 81 e2 ff 00 00 00 a1 ?? ?? ?? ?? 03 c2 50 8b 0d 04 03 4d fc 51 e8 ?? ?? ?? ?? 83 c4 08 8b 45 f8 25 ff 00 00 00 83 c0 01 99 f7 7d 0c 88 55 f8 eb}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 14 07 33 c0 8a 01 03 f2 03 c6 be ?? ?? ?? ?? 99 f7 fe [0-31] 81 e6 ff 00 00 00 [0-31] 83 c4 08 99 f7 7c 24 1c 43 81 fb 00 88 54 24 20 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_SD_2147766631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.SD!MTB"
        threat_id = "2147766631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b f0 6a ?? 8b ce e8 ?? ?? ?? ?? 8b ce e8 ?? ?? ?? ?? 0f b6 54 24 11 a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 20 30 0c 28 45 3b 6c 24 24 0f 8c ?? ?? ff ff 8b 44 24 28 8a 54 24 12 8a 4c 24 13 5f 5e 5b 88 10 88 48 01 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_MR_2147766714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.MR!MTB"
        threat_id = "2147766714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 02 8b 44 24 ?? 8a 14 03 32 d1 88 14 03 8b 44 24 ?? 43 3b d8 0f 8c 0f 00 8b 54 24 ?? a1 ?? ?? ?? ?? 81 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCX_2147766786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCX!MTB"
        threat_id = "2147766786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 1c 8b 15 ?? ?? ?? ?? 8b 44 24 ?? 81 e1 ff 00 00 00 8a 14 11 8b 4c 24 ?? 8a 1c 08 32 da 88 1c 08 8b 4c 24 ?? 40 3b c1 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_MS_2147767467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.MS!MTB"
        threat_id = "2147767467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 03 45 f8 89 45 e4 8b 4d f4 03 4d e8 89 4d f0 c7 05 [0-8] c7 05 [0-8] 8b 55 f4 c1 ea 05 89 55 ec 8b 45 ec 03 45 d4 89 45 ec 8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 45 d8 29 45 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d e4 03 d9 8b 4d f8 8b c6 c1 e8 05 03 45 e8 03 ce 33 d9 33 d8 c7 05 [0-8] c7 05 [0-8] 89 45 fc 2b fb 8b 45 e0 29 45 f8 83 6d f4 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_GKM_2147767532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.GKM!MTB"
        threat_id = "2147767532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 bd 5f 02 00 00 f7 fd a1 ?? ?? ?? ?? 0f b6 ea 03 c5 88 54 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_GKM_2147767532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.GKM!MTB"
        threat_id = "2147767532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 ?? 8b 35 ?? ?? ?? ?? 8b 44 24 ?? 8a 14 32 8b [0-3] 30 14 08 40 3b [0-3] 89 44 24 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_2147767639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.MT!MTB"
        threat_id = "2147767639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 d3 e0 c1 ee 05 03 74 24 38 03 44 24 2c 89 74 24 10 8b c8 e8 ?? ?? ?? ?? 33 c6 89 44 24 24 89 2d ?? ?? ?? ?? 8b 44 24 24 29 44 24 14 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_MU_2147767705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.MU!MTB"
        threat_id = "2147767705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e4 8b 45 f8 8b f3 c1 ee 05 03 75 e8 03 fa 03 c3 33 f8 81 3d [0-8] c7 05 [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f7 81 3d}  //weight: 1, accuracy: High
        $x_1_3 = {8b 7d fc 2b fe 81 3d [0-8] 89 7d fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCY_2147768383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCY!MTB"
        threat_id = "2147768383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4c 24 ?? 8b 15 ?? ?? ?? ?? 8a 0c 11 8b 44 24 ?? 30 0c 28 45 3b 6c 24 ?? 0f 8c ?? ?? ?? ?? 8b 44 24 ?? 8a 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PCZ_2147768384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCZ!MTB"
        threat_id = "2147768384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 20 8a 0c 32 8b 44 24 10 02 4c 24 30 8b 54 24 24 32 0c 02 40 ff 4c 24 18 88 48 ff 89 44 24 10 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PDA_2147768452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PDA!MTB"
        threat_id = "2147768452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 20 8a 0c 32 8b 44 24 14 02 4c 24 30 8b 54 24 24 32 0c 02 83 c0 01 83 6c 24 18 01 88 48 ff 89 44 24 14 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PDA_2147768452_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PDA!MTB"
        threat_id = "2147768452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 32 8b 44 24 ?? 02 4c 24 ?? 8b 54 24 ?? 32 0c 02 83 c0 01 83 6c 24 ?? 01 88 48 ff 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 8b 44 24 ?? 30 54 28 ?? 3b 6c 24 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 da 8b 54 24 ?? 0f b6 14 13 8d 0c 2f 03 d6 03 c2 99 be 2b 03 00 00 f7 fe 0f b6 f2 8d 04 2e e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 da 8b 54 24 ?? 0f b6 14 13 8d 0c 2f 03 d6 03 c2 99 be 9c 01 00 00 f7 fe 0f b6 f2 8d 04 2e e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 8a a5 08 00 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 83 05 ?? ?? ?? ?? ?? 83 05 ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 bf 24 01 00 00 f7 ff 0f b6 c2 8a 0c 08 8b 45 ?? 30 08 ff 45 ?? 8b 45 ?? 3b 45 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 99 bf 9d 02 00 00 f7 ff 0f b6 c2 8a 0c 08 8b 45 ?? 30 08 ff 45 ?? 8b 45 ?? 3b 45 ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 bf 77 02 00 00 f7 ff 8a 04 0e 0f b6 fa 8a 14 37 8d 2c 37 88 14 0e 88 45 00 8d 43 ?? 99 f7 7c 24 ?? 41 81 f9 77 02 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KMG_2147768668_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KMG!MTB"
        threat_id = "2147768668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 fa 0f b6 97 ?? ?? ?? ?? 8d 0c 06 0f b6 01 03 d3 03 c2 99 8b dd f7 fb 0f b6 da 8d 04 33 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 da 0f b6 93 ?? ?? ?? ?? 8d 0c 2f 03 d6 03 c2 99 be 95 02 00 00 f7 fe 0f b6 f2 8d 04 2e e8}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 da 0f b6 93 ?? ?? ?? ?? 8d 0c 2f 03 d6 03 c2 99 be c4 01 00 00 f7 fe 0f b6 f2 8d 04 2e e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PDB_2147770428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PDB!MTB"
        threat_id = "2147770428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 0f b6 13 03 c2 99 b9 ?? ?? ?? ?? f7 f9 a1 ?? ?? ?? ?? 46 0f b6 d2 8a 0c 02 8b 44 24 ?? 30 4c 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_MV_2147770510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.MV!MTB"
        threat_id = "2147770510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 8b 45 08 [0-5] 32 [0-3] 47 3b [0-3] 88 [0-5] 8b [0-5] ff [0-3] 8d [0-3] e8 [0-4] 59 33 [0-3] 8b [0-3] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PDC_2147771291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PDC!MTB"
        threat_id = "2147771291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 54 24 ?? a1 ?? ?? ?? ?? 8a 0c 02 8b 44 24 ?? 30 0c 28 45 83 c4 ?? 3b 6c 24 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_VA_2147771614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.VA!MTB"
        threat_id = "2147771614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 0f b6 c0 8b ce [0-20] 8b d7 0f b6 4d ?? 47 2b 15 ?? ?? ?? ?? 8a 04 ?? b9 ?? ?? ?? ?? 04 01 01 01 01 30 31 32 33 ?? ?? 8b 45 ?? 3b 7d ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_MZ_2147771696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.MZ!MTB"
        threat_id = "2147771696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 c8 83 c2 01 89 55 c8 83 7d c8 04 7d 16 c7 45 [0-5] 8b [0-2] 2b [0-2] 0f [0-3] 89 45 ?? ?? ?? c7 45 [0-5] 8d [0-2] 89 [0-2] 8b [0-2] 8b 02 0d [0-4] 8b [0-2] 81 [0-5] 0f [0-2] 8b [0-2] 2b d0 89 [0-4] 8b [0-2] 8b [0-2] 8b [0-2] 89 [0-2] e9}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 [0-2] c7 45 [0-5] 8b [0-2] 33 [0-2] 89 [0-2] c7 45 [0-5] c7 45 [0-5] c7 45 [0-5] 8b [0-2] 83 [0-2] 0f [0-3] 8b [0-2] 99 f7 ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_D_2147771995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.D!MTB"
        threat_id = "2147771995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b d8 8b 0d ?? ?? ?? ?? 33 d2 8b c1 f7 f3 03 55 18 8a 04 32 8b 55 0c 32 04 0a 8b 55 10 88 04 0a ff 05 ?? ?? ?? ?? 39 3d ?? ?? ?? ?? 75 cb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 03 45 fc 8a 08 32 ca 8b 55 08 03 55 fc 88 0a 8b 45 f8 83 c0 01 89 45 f8 8b 45 fc 99 b9 05 00 00 00 f7 f9 85 d2 75 07 c7 45 f8 00 00 00 00 eb a8 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 14 0f 88 14 0e 88 04 0f 0f b6 14 0f 0f b6 04 0e 03 c2 99 f7 fb 0f b6 c2 0f b6 14 08 30 55 ff 83 6c 24 14 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_E_2147772322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.E!MTB"
        threat_id = "2147772322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 8b c7 2b 05 ?? ?? ?? ?? 47 03 c8 0f b6 c3 8b 1d ?? ?? ?? ?? 8a 04 18 30 01 8b 4d f4 3b fe 7c ?? 8b 75 08 8a 45 ff 88 06 8a 45 fe 5f 88 46 01 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KM_2147772361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KM!MTB"
        threat_id = "2147772361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 0f b6 4d ?? 8a 0c 11 30 08 ff 45 ?? 8b 45 ?? 3b 45 ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_KM_2147772361_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.KM!MTB"
        threat_id = "2147772361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 29 09 00 00 e8 ?? ?? ?? ?? 83 c4 04 a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 94 01 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? ?? 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d 29 09 00 00 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 72 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_F_2147772397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.F!MTB"
        threat_id = "2147772397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8d 45 e8 ff 75 e8 50 56 6a 00 6a 01 6a 00 ff 75 d4 ff 15 ?? ?? ?? ?? 85 c0 74 1c ff 75 e8 8d 4d ef 56 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 8d 4d ef e8 ?? ?? ?? ?? ff d0 8b 4d fc 5f 33 cd 33 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PDD_2147772921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PDD!MTB"
        threat_id = "2147772921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 25 49 92 24 f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 04 8d 0c c5 00 00 00 00 2b c8 03 c9 03 c9 8b d6 2b d1 8a 04 2a 30 04 3e}  //weight: 1, accuracy: High
        $x_1_2 = "LcoKbtNEyJYeCR2WCqZuHxgp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_AV_2147773158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AV!MTB"
        threat_id = "2147773158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 08 2b ca 8b 55 08 89 0a 5e 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_AV_2147773158_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AV!MTB"
        threat_id = "2147773158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d be ac 00 00 a3 9c 63 00 10}  //weight: 1, accuracy: High
        $x_2_2 = {8b 45 08 8b 08 2b ca 8b 55 08 89 0a 5e 8b e5 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_AV_2147773158_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.AV!MTB"
        threat_id = "2147773158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 01 88 02 88 19 0f b6 0a 0f b6 c3 03 c8 0f b6 c1 8a 8d ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 30 04 3e 46 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PDE_2147773521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PDE!MTB"
        threat_id = "2147773521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 0c 3a 33 d2 0f b6 c1 8b ce 0f b6 0c 39 03 c1 f7 35 ?? ?? ?? ?? 8b f2 ff 15 ?? ?? ?? ?? 8b 4d 18 8a 04 0b 32 04 3e 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_PDE_2147773521_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PDE!MTB"
        threat_id = "2147773521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZombifyActCtx" ascii //weight: 1
        $x_1_2 = "JetRollback" ascii //weight: 1
        $x_1_3 = "BybigCtIXTe454t" ascii //weight: 1
        $x_1_4 = "GetUserGeoID" ascii //weight: 1
        $x_1_5 = "Posted" ascii //weight: 1
        $x_1_6 = "mailcom" ascii //weight: 1
        $x_1_7 = "comview" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_RR_2147805203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.RR!MTB"
        threat_id = "2147805203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kqjghvpsgcmjy.dll" ascii //weight: 1
        $x_1_2 = "Control_RunDLL" ascii //weight: 1
        $x_1_3 = "beokzxuancasxutuo" ascii //weight: 1
        $x_1_4 = "ewpvpregilczxln" ascii //weight: 1
        $x_1_5 = "exxqkgcydkyzrjrqd" ascii //weight: 1
        $x_1_6 = "fdsyyzuhyg" ascii //weight: 1
        $x_1_7 = "ggnkkuc" ascii //weight: 1
        $x_1_8 = "psxorbjnbypn" ascii //weight: 1
        $x_1_9 = "uszyonebupzgchxv" ascii //weight: 1
        $x_1_10 = "vkolzxxwqfj" ascii //weight: 1
        $x_1_11 = "wkfflvfmqa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DC_2147805223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DC!MTB"
        threat_id = "2147805223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 8d 0c 39 f7 e1 8b cb 8d 7f ?? c1 ea 02 83 c3 06 6b c2 0d 2b c8 0f b6 44 8d ?? 30 47 ff 81 fb 00 34 02 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DD_2147805348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DD!MTB"
        threat_id = "2147805348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 8b 44 24 14 03 c2 8b 54 24 34 0f b6 14 32 89 44 24 1c 8b 44 24 30 0f b6 04 08 03 c2 33 d2 bf ?? ?? ?? ?? f7 f7 8b 7c 24 1c 03 d3 8a 04 2a 30 07 ff 44 24 10 81 7c 24 10 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DE_2147805350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DE!MTB"
        threat_id = "2147805350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 03 0f af 0d ?? ?? ?? ?? 03 c8 8b 44 24 14 03 ca 03 d9 8a 0c 33 8a 18 32 d9 8b 4c 24 24 88 18 8b 44 24 10 40 3b c1 89 44 24 10 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "nC?Lq4?x_0tySlxQ#5k8CX_N@CUR45R%w1+dZ4*>XT6Rl<ux#6jBM9&?18p46&?(eRF^U^ljvwMnMfI%v)JmKU)+<cS6!voS(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DF_2147805537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DF!MTB"
        threat_id = "2147805537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 0e 29 d0 8b 54 24 08 88 1c 0a 01 c1 89 4c 24 1c 8b 44 24 18 35 [0-4] 3d [0-4] 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DF_2147805537_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DF!MTB"
        threat_id = "2147805537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 08 e9 46 00 [0-32] 33 d1 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 4d ?? 2b 0d ?? ?? ?? ?? 2b c8 2b 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c2 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 8b 75 ?? 2b f2 2b f1 03 35 ?? ?? ?? ?? 03 35 ?? ?? ?? ?? 8b 4d ?? 88 04 31 e9}  //weight: 1, accuracy: Low
        $x_1_3 = "y_fvA2fuV#qhZ0tas>i@?Audict*xl_G(GwW%XMIv87I+<tCDcKOB*vsl" ascii //weight: 1
        $x_1_4 = "a_BY$a$5^0ilcp6!kHgBSXQK5S7_%Vb)aCoO9ZC4Veq8NhEKtP7@WBOO(TEZT?^k6lb^RLBQu)!AT)Fl@*TGa$h+Ip" ascii //weight: 1
        $x_1_5 = "(^tMK&16v4A2HS!$pqKvCS0AW<vnlnjivRSP6mM1eN2SqnGcS)*mZso7MEWLRwkmkI1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DG_2147805538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DG!MTB"
        threat_id = "2147805538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2a 03 c2 33 d2 89 6c 24 18 bd ?? ?? ?? ?? f7 f5 8b 44 24 44 8b 6c 24 20 83 c5 01 89 6c 24 20 2b 54 24 14 2b 54 24 1c 2b d7 2b d1 03 d6 0f b6 14 02 8b 44 24 3c 30 54 28 ff 81 fd 00 34 02 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DH_2147805539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DH!MTB"
        threat_id = "2147805539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c3 83 c0 02 0f af c1 8d 4e 01 03 d0 0f af 0d ?? ?? ?? ?? 8b 44 24 1c 2b d1 8b 0d ?? ?? ?? ?? 8a 18 2b d1 03 d6 8b 4c 24 24 8a 14 3a 32 da 88 18}  //weight: 1, accuracy: Low
        $x_1_2 = "?D!u?X)krTzdw$anM4p_$bzQ?j7?rEn98An?3+0V>Z@rx1%ppm(VMCs$6kTXkM4n9UaGO^3gLOFIgj<istQICX4+VcVyt+YUU@Q3jGK4Lp9$gWv1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DJ_2147805735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DJ!MTB"
        threat_id = "2147805735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 2a 03 c2 33 d2 89 6c 24 18 bd ?? ?? ?? ?? f7 f5 8b 44 24 44 8b 6c 24 20 83 c5 01 89 6c 24 20 2b 54 24 14 2b 54 24 1c 2b d7 2b d1 03 d6 0f b6 14 02 8b 44 24 3c 30 54 28 ff 81 fd ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "lEZ4zx89^n^orFIbWKOvbN1Kp4M&%G+77OI^Bna85p8yypN_4Oe#lJbL*Uoq@YZ_FT&Q^_87STI7?hC60A0&d*bMP@?N5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DK_2147805758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DK!MTB"
        threat_id = "2147805758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? 89 55 f8 8b 45 08 03 45 ec 33 c9 8a 08 8b 55 fc 03 55 f8 33 c0 8a 02 33 c8 8b 55 18 03 55 ec 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "dWyDIhQ(*fSeoreDWt9D&E+8teUTsaw%@I@7G9+3OB0X0JscABLO" ascii //weight: 1
        $x_1_3 = {57 57 ff d6 57 57 ff d6 8b 45 e8 8a 0c 18 02 4d ff 8b 45 f0 8b 55 e4 32 0c 02 88 08 40 ff 4d 0c 89 45 f0 0f 85}  //weight: 1, accuracy: High
        $x_1_4 = "rK0P+XX%@Yap9cdr)HyV<ve7qK6+BEWhQ>^AYp2atJ#NLjszUlL@cdlES_oTnDNwdm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DM_2147805906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DM!MTB"
        threat_id = "2147805906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 5c 24 14 0f b6 14 3b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 03 ca 8d 04 71 8a 0c 38 8b 44 24 20 30 08 ff 44 24 18 8b 44 24 18 3b 44 24 28 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = "C6Ne<&!n7b?TKj0wku<)yQKB3xBs(OyE04(u1fxyib5hh(BSEDxRasVb<5lveJB7A&Wh5Qk4l)U1XJLO0yKdMggRSSd*f5" ascii //weight: 1
        $x_1_3 = {8b 5c 24 28 0f b6 14 1a 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 20 2b d1 8a 0c 1a 30 08 ff 44 24 18 8b 44 24 18 3b 44 24 30 0f 82}  //weight: 1, accuracy: Low
        $x_1_4 = "O0!f?czm?9chhum)if$$ZF06ci*@82<3JI?oKbz^4!PcDupvhakIfbVCzJawebI1jyGyjh*lPbev0s1MkaqhSn<Ad))aaS$x4+?C<ct01*<Zit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DN_2147805907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DN!MTB"
        threat_id = "2147805907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 8d c4 30 47 02 b8 ?? ?? ?? ?? 8b 4d f4 8d 0c 39 f7 e1 8b cb 8d 7f 04 c1 ea 02 83 c3 04 6b c2 0d 2b c8 0f b6 44 8d c8 30 47 ff 81 fb ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_EmotetCrypt_DO_2147805932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.DO!MTB"
        threat_id = "2147805932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 da 2b d9 03 5c 24 14 0f b6 14 3b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 03 ca 8d 04 71 8a 0c 38 8b 44 24 20 30 08}  //weight: 5, accuracy: Low
        $x_1_2 = "%qQn1+%2DtahH8KP%_JEsNTIeFuWp46O<sq5j2iVN0tl(mSbqgb5zh2)YQ$D5s^8j" ascii //weight: 1
        $x_5_3 = {8b 4c 24 1c 8b 44 24 10 8a 14 01 8a 4c 3c 20 32 d1 88 10 40 89 44 24 10 8b 44 24 14 48 89 44 24 14 0f 85}  //weight: 5, accuracy: High
        $x_1_4 = "Dl6IXXP5fi#yNy4GFs*YP9eMxYRO$iX4|ZG|D$Ts9f}ab@BgYsWye2#TsLP#q4ew0*vB%l}M*87WY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_EmotetCrypt_PCJ_2147899380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EmotetCrypt.PCJ!MTB"
        threat_id = "2147899380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EmotetCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 2c 83 f0 ff 89 44 24 2c 8b 44 24 24 8a 3c 30 28 df 8b 54 24 20 88 3c 32 83 c6 25 8b 7c 24 28 39 fe 89 74 24 14 0f 82}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 4c 8b 4c 24 34 8a 54 24 4b 8a 30 28 d6 8b 44 24 24 88 34 08 8b 4c 24 34 83 c1 33 89 4c 24 50 8b 74 24 2c 39 f1 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

