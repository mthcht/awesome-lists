rule Trojan_Win32_CryptInject_2147725859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject"
        threat_id = "2147725859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 ?? 8a 10 90 80 f2 ?? 88 10 90 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 06 90 90 8b 06 03 c3 73 ?? e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 90 ff 06 81 3e ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_2147725859_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject"
        threat_id = "2147725859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 f6 2b 37 f7 de 83 c7 05 4f f7 d6 83 ee d7 01 de 83 ee 00 4e 8d 1e 56 8f 41 00 8d 49 04 83 ea 03 4a 85 d2 75 da 83 c4 04 8b 4c 24 fc 8d 15 ?? ?? ?? ?? ff 32 ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 00 6b c6 40 01 65 c6 40 02 72 c6 40 03 6e c6 40 04 65 c6 40 05 6c c6 40 06 33 50 8d 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_A_2147727945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.A"
        threat_id = "2147727945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 55 8b ec 8b 45 ?? 90 90 8a 10 80 f2 ?? 88 10 90 90 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 89 06 8b 06 03 c3 73 ?? e8 ?? ?? ?? ?? 50 ff 15 60 6e 46 00 90 90 ff 06 81 3e c5 5a 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AN_2147729384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AN!MTB"
        threat_id = "2147729384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hzjfazkrifbj" ascii //weight: 2
        $x_2_2 = "mRZVOZqAOLWnRoO" ascii //weight: 2
        $x_2_3 = "rmhulzswvnjdhy" ascii //weight: 2
        $x_2_4 = "xeZXHeQkfwCh" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AN_2147729384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AN!MTB"
        threat_id = "2147729384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 03 f1 8b 08 13 ea 8b c7 6b c0 ?? 81 7c 24 18 ?? ?? ?? ?? 89 0d ?? ?? ?? 00 8d 0c 18}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 1c 13 c2 8b f3 8b e8 0f b6 0d ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 54 24 10 05 ?? ?? ?? ?? 8d 1c b9 a3 ?? ?? ?? 00 89 02 8d 44 1b ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_VT_2147729716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.VT!MTB"
        threat_id = "2147729716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 75 f8 80 36 f9 90 90 ff 45 fc 81 7d fc 1a 5a 00 00 75 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {74 7c 59 04 06 06 a9 06 ae a9 aa 06 6e 55 f9 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_Y_2147733294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.Y"
        threat_id = "2147733294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 b8 d0 00 00 e9 7f fe ff ff cc cc cc cc cc cc cc cc cc cc cc cc 57 56 8b 74 24 10 8b 4c 24 14 8b 7c 24 0c}  //weight: 1, accuracy: High
        $x_1_2 = "F0F213B0799197FD119171680EC79CA91" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_H_2147733342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.H"
        threat_id = "2147733342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 61 00 63 00 43 00 45 00 4e 00 54 00 55 00 72 00 45 00}  //weight: 1, accuracy: High
        $x_1_2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANTDLL.DLL" ascii //weight: 1
        $x_1_3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKERNEL32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_I_2147733348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.I"
        threat_id = "2147733348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SDKLHJKSDLHJXCKCSDFCSDFSDF#kERNEL32" ascii //weight: 1
        $x_1_2 = "JKLDFHSDGHJKFSDJHGFSDGHJFSDGHJFGHJSDHJGSDF#GlobalAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_K_2147733515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.K"
        threat_id = "2147733515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 85 33 ff ff ff 23 c6 85 13 ff ff ff 30 c6 85 72 fe ff ff 8b c6 85 6a fd ff ff 6b c6 85 fc fb ff ff 8a c6 85 f8 f9 ff ff 77 c6 85 25 f9 ff ff 80 c6 85 a9 f8 ff ff 59}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 c7 6c c6 85 21 ff ff ff c5 c6 85 54 fd ff ff c1 c6 85 2d fb ff ff a4 c6 85 55 f9 ff ff 52 c6 85 b3 f8 ff ff 0e c6 85 17 f8 ff ff 32 c6 85 21 f6 ff ff d3 c6 85 55 f5 ff ff 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_K_2147733515_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.K"
        threat_id = "2147733515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 c4 66 c6 85 2f ff ff ff 6c c6 85 89 fe ff ff c5 c6 85 bc fc ff ff c1 c6 85 95 fa ff ff a4 c6 85 bd f8 ff ff 52 c6 85 1b f8 ff ff 0e c6 85 7f f7 ff ff 32 c6 85 89 f5 ff ff d3 c6 85 bd f4 ff ff 33}  //weight: 1, accuracy: High
        $x_1_2 = {c6 85 8d fd ff ff 38 c6 85 47 fd ff ff 85 c6 85 fb fa ff ff d4 c6 85 07 fa ff ff 74 c6 85 ee f8 ff ff 7f c6 85 8f f7 ff ff 08 c6 85 be f6 ff ff 5e c6 85 69 f6 ff ff fb c6 85 f2 f3 ff ff 56 c6 85 1b f3 ff ff 89 c6 85 b3 f2 ff ff 0e c6 85 30 f1 ff ff 16 c6 85 41 ef ff ff 9b c6 85 bc ee ff ff 82 c6 85 41 ee ff ff a9 c6 85 21 ee ff ff 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YG_2147733947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YG!MTB"
        threat_id = "2147733947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 08 8b 0a 0f b6 14 01 03 c8 88 55 fe 0f b6 51 01 88 55 fd 0f b6 51 02 88 55 fc 8a 51 03 89 5d f8 83 45 f8 02 89 5d f4 83 45 f4 04 8b 4d f8 8a da d2 e3 8b 4d f4 80 e3 c0 0a 5d fe 88 1c 3e 8a da d2 e3 c0 e2 06 0a 55 fc 80 e3 c0 0a 5d fd 80 ea 02 88 5c 3e 01 88 55 ff 80 45 ff 02 8a 4d ff 88 4c 3e 02 8b 4d 0c 83 c0 04 83 c6 03 3b 01 72 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AA_2147733949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AA"
        threat_id = "2147733949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 00 c6 05 ?? ?? 40 00 6e c6 05 ?? ?? 40 00 74 8d 35 ?? ?? 40 00 56}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 07 f8 83 d7 04 f7 ?? 83 c0 da f8 83 d0 ff 29 c8 6a ff 59 21 c1 89 02 83 c2 04 f8 83 de 04 85 f6 75 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_P_2147733953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.P"
        threat_id = "2147733953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GmsuXEVt=#+%DrB&p>/q" wide //weight: 1
        $x_1_2 = "\\Gleaned\\purecall\\win32p6.pdb" ascii //weight: 1
        $x_1_3 = "theoff.asksPBP8whichextensions" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_CryptInject_AB_2147734132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AB"
        threat_id = "2147734132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GmsuXEVt=#+%DrB&p>/q" wide //weight: 1
        $x_1_2 = "fromfuckyouxand" wide //weight: 1
        $x_1_3 = "failed.fKelectedpJulyandhas" ascii //weight: 1
        $x_1_4 = "releases\\o56GtreadDesktopv83045p6.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YH_2147734633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YH!MTB"
        threat_id = "2147734633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8b f2 33 c0 57 8b f9 85 f6 7e 1d 0f 1f 40 00 8a 0c 38 8b d0 83 e2 ?? 80 e9 ?? 32 8a ?? ?? ?? ?? 88 0c 38 40 3b c6 7c e7 5f 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AK_2147735731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AK"
        threat_id = "2147735731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 3a 5c 43 6f 64 65 5c 4d 61 63 72 6f [0-2] 4e 42 32 5c 52 65 71 75 65 73 74 5c 50 6f 73 74 44 61 74 61 [0-3] 2e 65 78 65 [0-5] 2d 75 20 68 74 74 70 73 3a 2f 2f 63 6f 72 74 61 6e 61 73 79 6e 2e 63 6f 6d 2f 6b 69 72 72 [0-3] 2e 70 6e 67 20 2d 74 20 32 30 30 30 30 30}  //weight: 1, accuracy: Low
        $x_1_2 = {41 3a 5c 43 6f 64 65 5c 4d 61 63 72 6f [0-2] 4e 42 32 5c 52 65 71 75 65 73 74 5c 50 6f 73 74 44 61 74 61 [0-3] 2e 65 78 65 [0-5] 2d 75 20 68 74 74 70 73 3a 2f 2f 73 79 6e 2e 73 65 72 76 65 62 62 73 2e 63 6f 6d 2f 6b 75 73 73 [0-3] 2e 67 69 66 20 2d 74 20 32 30 30 30 30 30}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 4d 61 63 72 6f [0-2] 4e 42 32 [0-2] 6e 65 77 5c 52 65 71 75 65 73 74 5c 50 6f 73 74 44 61 74 61 [0-3] 2e 65 78 65 [0-5] 2d 75 20 68 74 74 70 73 3a 2f 2f 6f 66 66 69 63 65 2e 61 6c 6c 73 61 66 65 62 72 6f 77 73 69 6e 67 2e 63 6f 6d 2f 66 64 73 77 [0-3] 2e 70 6e 67 20 2d 74 20 32 34 30 30 30 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_YI_2147735828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YI!MTB"
        threat_id = "2147735828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 fc 4b 46 00 50 e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33 ?? ?? ?? ?? ?? ?? ?? ?? [0-10] a1 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 73 ?? e8 ?? ?? ?? ff [0-10] a3 ?? ?? ?? 00 [0-10] 8a ?? 34 ?? a2 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YK_2147735958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YK!MTB"
        threat_id = "2147735958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 05 8d 0c 30 8a 41 03 8a d0 8a d8 80 e2 f0 80 e3 fc c0 e2 02 0a 11 c0 e0 06 0a 41 02 c0 e3 04 0a 59 01 8b 4d f4 88 14 0f 47 88 1c 0f 47 89 7d f8 88 04 0f 8d 7d f8 e8 44 ff ff ff 03 75 fc 8b 7d f8 3b 35 ?? ?? 28 05 72 b3}  //weight: 1, accuracy: Low
        $x_1_2 = {64 a1 00 00 00 00 50 64 89 25 00 00 00 00 [0-20] 42 00 c6 05 ?? ?? ?? 05 6b c6 05 ?? ?? ?? 05 6c c6 05 ?? ?? ?? 05 33 c6 05 ?? ?? ?? 05 6e c6 05 ?? ?? ?? 05 65 c6 05 ?? ?? ?? 05 32 c6 05 ?? ?? ?? 05 6c c6 05 ?? ?? ?? 05 65 c6 05 ?? ?? ?? 05 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YJ_2147735975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YJ!MTB"
        threat_id = "2147735975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 3e 89 ?? 24 0c e8 ?? f6 ff ff 89 44 24 10 8b 44 24 0c 33 44 24 10 89 44 24 0c 8a 4c 24 0c 88 0c 3e 46 3b f3 7c d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YM_2147739748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YM!MTB"
        threat_id = "2147739748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 0c 53 c7 45 f8 06 ba ec 9e 81 45 f8 24 d1 fd 2b 35 b8 43 2b 27 81 45 f8 d6 74 15 35 c1 e3 11 81 45 f8 fd 43 03 00 a1 ?? ?? ?? 00 0f af 45 f8 83 65 fc 00 a3 ?? ?? ?? 00 bb 7b 1f be 69 81 6d fc 78 b1 af 32 81 45 fc 78 b1 af 32 81 f3 3e ff 7f 22 35 9b fe b9 69 81 45 fc c3 9e 26 00 a1 ?? ?? ?? 00 03 45 fc 83 65 f4 00 a3 ?? ?? ?? 00 81 f3 d2 ab 0e 49 81 6d f4 98 18 6f 3c 81 45 f4 a8 18 6f 3c 8b 4d f4 d3 e8 5b 25 ff 7f 00 00 c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YL_2147739792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YL!MTB"
        threat_id = "2147739792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 5a 90 8b 15 e8 1d 47 00 8a 92 38 44 46 00 88 15 f0 1d 47 00 8b d6 03 d3 89 15 e0 1d 47 00 30 05 f0 1d 47 00 90 90 a1 e0 1d 47 00 8a 15 f0 1d 47 00 88 10 90 90 83 05 e8 1d 47 00 02 43 81 fb 5d 5b 00 00 75 ba}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YN_2147739936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YN!MTB"
        threat_id = "2147739936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
        $x_1_3 = {52 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
        $x_1_4 = {53 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
        $x_1_5 = {54 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
        $x_1_6 = {55 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
        $x_1_7 = {56 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
        $x_1_8 = {57 6a 40 68 ?? ?? 00 00 [0-6] e8 ?? ?? ?? ff [0-10] 33 ?? a3 ?? ?? ?? 00 [0-10] 33 ?? [0-10] 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_YO_2147740436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YO!MTB"
        threat_id = "2147740436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 18 8d 4c 24 28 80 00 b1 72 68 ?? ?? ?? 00 50 89 ?? ?? ?? ?? 00 c6 05 ?? ?? ?? 00 50 88 0d ?? ?? ?? 00 c6 05 ?? ?? ?? 00 6f c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 63 c6 05 ?? ?? ?? 00 00 c6 05 ?? ?? ?? 00 56 c6 05 ?? ?? ?? 00 69 88 0d ?? ?? ?? 00 c6 05 ?? ?? ?? 00 75 c6 05 ?? ?? ?? 00 61 c6 05 ?? ?? ?? 00 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YQ_2147740438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YQ!MTB"
        threat_id = "2147740438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 f1 a0 fa ff 90 83 ?? ?? ?? ?? ?? ?? 76 ?? [0-10] b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b f0 [0-10] 33 c0 a3 ?? ?? ?? 00 [0-10] 33 c0 a3 ?? ?? ?? 00 90 c6 ?? ?? ?? ?? ?? ?? 33 c0 89 03 b8 ?? ?? ?? 00 8b d6 03 13 8a ?? ?? ?? ?? 00 32 08 88 0a ff 03 40 81 ?? ?? ?? ?? ?? ?? ?? ?? 8b c6 83 c0 ?? 89 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YR_2147741058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YR!MTB"
        threat_id = "2147741058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {dd d8 c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 2e c6 05 ?? ?? ?? 00 6e c6 05 ?? ?? ?? 00 33 c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 64 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 32 c6 05 ?? ?? ?? 00 72 c6 05 ?? ?? ?? 00 6b c6 05 ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YS_2147741112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YS!MTB"
        threat_id = "2147741112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb c9 c6 05 ?? ?? ?? 00 72 c6 05 ?? ?? ?? 00 74 c6 05 ?? ?? ?? 00 61 c6 05 ?? ?? ?? 00 6f c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 74 c6 05 ?? ?? ?? 00 69 c6 05 ?? ?? ?? 00 56 c6 05 ?? ?? ?? 00 72 c6 05 ?? ?? ?? 00 50 c6 05 ?? ?? ?? 00 75 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 63 c6 05 ?? ?? ?? 00 74 c6 05 ?? ?? ?? 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YT_2147741113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YT!MTB"
        threat_id = "2147741113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f4 c6 64 00 c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 2e c6 05 ?? ?? ?? 00 6e c6 05 ?? ?? ?? 00 33 c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 64 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 32 c6 05 ?? ?? ?? 00 72 c6 05 ?? ?? ?? 00 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YU_2147741114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YU!MTB"
        threat_id = "2147741114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc b8 ?? ?? 00 00 e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b [0-10] 8a ?? ?? ?? ?? 00 [0-10] 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YV_2147741173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YV!MTB"
        threat_id = "2147741173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b ?? ?? 25 ff 00 00 00 0f b6 c8 51 e8 ?? ?? ?? ?? 83 c4 04 8b 45 08 8b 55 0c b1 ?? e8 ?? ?? ?? ?? 25 ff 00 00 00 0f b6 d0 52}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec a1 ?? ?? ?? 00 c1 e8 ?? 25 ff ff ff 00 0f b6 4d 08 33 ?? ?? ?? ?? 00 81 e1 ff 00 00 00 33 04 ?? ?? ?? ?? 00 a3 ?? ?? ?? 00 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YW_2147741246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YW!MTB"
        threat_id = "2147741246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 8b e8 b8 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b [0-10] 3d [0-15] 8a ?? ?? ?? ?? 00 [0-10] 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YX_2147741247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YX!MTB"
        threat_id = "2147741247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 50 [0-14] e8 ?? ?? ?? ff [0-14] e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b ?? [0-10] 8a ?? ?? ?? ?? 00 [0-10] 34}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 [0-14] e8 ?? ?? ?? ff [0-14] e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b ?? [0-10] 8a ?? ?? ?? ?? 00 [0-10] 34}  //weight: 1, accuracy: Low
        $x_1_3 = {55 8b ec 52 [0-14] e8 ?? ?? ?? ff [0-14] e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b ?? [0-10] 8a ?? ?? ?? ?? 00 [0-10] 34}  //weight: 1, accuracy: Low
        $x_1_4 = {55 8b ec 53 [0-14] e8 ?? ?? ?? ff [0-14] e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b ?? [0-10] 8a ?? ?? ?? ?? 00 [0-10] 34}  //weight: 1, accuracy: Low
        $x_1_5 = {55 8b ec 56 [0-14] e8 ?? ?? ?? ff [0-14] e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b ?? [0-10] 8a ?? ?? ?? ?? 00 [0-10] 34}  //weight: 1, accuracy: Low
        $x_1_6 = {55 8b ec 57 [0-14] e8 ?? ?? ?? ff [0-14] e8 ?? ?? ?? ff 8b ?? [0-10] 33 ?? [0-10] 8b ?? [0-10] 8a ?? ?? ?? ?? 00 [0-10] 34}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_YY_2147741299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YY!MTB"
        threat_id = "2147741299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 85 3c ff ff ff c0 00 c6 05 ?? ?? ?? 00 6b c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 72 c6 05 ?? ?? ?? 00 6e c6 05 ?? ?? ?? 00 65 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 33 c6 05 ?? ?? ?? 00 32 c6 05 ?? ?? ?? 00 2e c6 05 ?? ?? ?? 00 64 c6 05 ?? ?? ?? 00 6c c6 05 ?? ?? ?? 00 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YZ_2147741438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YZ!MTB"
        threat_id = "2147741438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 41 3b cf 72 ?? 68 ?? ?? ?? 00 6a 40 ?? ?? ff 15 ?? ?? ?? 00 8b 4d f4 8b 55 f8 8a 45 ff 30 02 42 e2 ?? ff ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAA_2147741709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAA!MTB"
        threat_id = "2147741709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 33 db 66 ?? ?? ?? ?? ?? ?? 6c 00 c6 ?? ?? ?? ?? 00 6b c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 66 c7 05 ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 66 c7 05 ?? ?? ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 56 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAB_2147741749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAB!MTB"
        threat_id = "2147741749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 e8 [0-32] 4b 75 ?? e8 ?? ?? ?? ff [0-32] [0-10] 85 [0-16] [0-10] 8b c8 03 cb [0-10] c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BM_2147741862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BM!MTB"
        threat_id = "2147741862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 88 06 00 00 57 85 f6 74 ?? 31 c0 33 03 83 eb fc 83 e8 33 c1 c8 08 29 d0 83 e8 01 8d 10 c1 c2 09 d1 ca 6a 00 8f 07 01 47 00 83 c7 04 83 ee 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BM_2147741862_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BM!MTB"
        threat_id = "2147741862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 94 2a ?? ?? ?? ?? 8a 19 32 da 83 c0 05 3d ?? ?? ?? ?? 88 19 0f 8c ?? ?? ff ff [0-79] 68 00 30 00 00 [0-47] 6a 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {75 0e 8a 85 ?? ?? ?? ?? 8b 4d 04 34 ?? 88 41}  //weight: 1, accuracy: Low
        $x_1_3 = {75 0f 8a 8d ?? ?? ?? ?? 8b 55 04 80 f1 ?? 88 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BS_2147741863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BS!MTB"
        threat_id = "2147741863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 45 [0-3] 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 ?? 6a 00 e8 ?? ?? ?? ?? 2b d8 01 5d ?? 8b 45 ?? 3b 45 ?? 72 40 00 01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BS_2147741863_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BS!MTB"
        threat_id = "2147741863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 32 d0 13 00 7c ?? 81 05 ?? ?? ?? ?? c1 3b 0f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ec 00 04 00 00 53 56 57 8b fa 33 f6 8b d9 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8d 9b 00 00 00 00 e8 ?? ?? ?? ?? 30 04 1e 81 ff 79 06 00 00 75 ?? 8d 44 24 10 50 6a 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAC_2147741874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAC!MTB"
        threat_id = "2147741874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 2b ca 8d ?? ?? ?? 33 c9 89 ?? ?? fc ff ff 89 ?? ?? fc ff ff 85 d2 74 ?? 8a ?? ?? ?? 30 14 19 83 ff ?? 75 ?? 33 ff eb ?? 47 41 3b ?? ?? fc ff ff 72 ?? 8b ?? ?? ?? 68 ?? ?? ?? 00 6a 40 50 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_GTLM_2147742129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.GTLM!MTB"
        threat_id = "2147742129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8a 1c 0a 33 d2 f7 f7 8b 45 ?? 8a 04 02 32 c3 88 01 0f be c3 c1 f8 ?? 83 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BA_2147742131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BA!MTB"
        threat_id = "2147742131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 f1 f0 f0 f0 f7 e6 c1 ea 05 8b c2 c1 e0 04 03 c2 03 c0 8b de 2b d8 8b 44 24 ?? 03 fe 3b 58 ?? 76 ?? e8 ?? ?? ?? ?? 8b 44 24 14 83 78 ?? 10 72 ?? 83 c0 04 8b 00 eb ?? 83 c0 04 8a 0c 18 30 0f 8b 45 ?? 2b 45 ?? 46 3b f0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SD_2147742135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SD!MTB"
        threat_id = "2147742135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Programme\\Autostart\\" ascii //weight: 1
        $x_1_2 = "\\exc.exe" ascii //weight: 1
        $x_1_3 = "Win32.crAcker.A" ascii //weight: 1
        $x_1_4 = "youporn.com" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SD_2147742135_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SD!MTB"
        threat_id = "2147742135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 01 a3 [0-8] 8b 15 ?? ?? ?? ?? 8b c0 83 c2 01 ?? ?? a1 ?? ?? ?? ?? 8b c0 8b ca 8b c0 a3 ?? ?? ?? ?? 8b c0 31 0d ?? ?? ?? ?? 8b c0 a1 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MR1_2147742523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MR1!MTB"
        threat_id = "2147742523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 c0 33 d2 8b 45 ?? 89 5d ?? 8a 0c 06 8b c6 f7 75 ?? 8b 45 ?? 88 4d ?? 8a 04 02 32 c1 8b 4d ?? 88 04 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BC_2147742628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BC!MTB"
        threat_id = "2147742628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {86 5a 88 3a 81 ac 24 ?? ?? ?? ?? 4c ab 80 7e 81 ac 24 ?? ?? ?? ?? 53 27 aa 0d 81 84 24 ?? ?? ?? ?? 72 9d 8b 2b 81 ac 24 ?? ?? ?? ?? e6 c7 05 56 81 84 24 ?? ?? ?? ?? 9c 98 05 02 81 ac 24 ?? ?? ?? ?? 64 a8 54 29 81 84 24 ?? ?? ?? ?? d8 0c c6 5d 81 ac 24 ?? ?? ?? ?? 7c e4 0d 1b 81 84 24 ?? ?? ?? ?? 7c 17 b6 7c 81 ac 24 ?? ?? ?? ?? 3e 89 76 08 81 84 24 ?? ?? ?? ?? 85 05 b4 60 81 ac 24 ?? ?? ?? ?? 80 db 1e 60 81 05 ?? ?? ?? ?? 85 c5 0a 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {86 5a 88 3a 81 ad ?? ?? ?? ?? 4c ab 80 7e 81 ad ?? ?? ?? ?? 53 27 aa 0d 81 85 ?? ?? ?? ?? 72 9d 8b 2b 81 ad ?? ?? ?? ?? e6 c7 05 56 81 85 ?? ?? ?? ?? 9c 98 05 02 81 ad ?? ?? ?? ?? 64 a8 54 29 81 85 ?? ?? ?? ?? d8 0c c6 5d 81 ad ?? ?? ?? ?? 7c e4 0d 1b 81 85 ?? ?? ?? ?? 7c 17 b6 7c 81 ad ?? ?? ?? ?? 3e 89 76 08 81 85 ?? ?? ?? ?? 85 05 b4 60 81 ad ?? ?? ?? ?? 80 db 1e 60 81 05 ?? ?? ?? ?? 85 c5 0a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_BD_2147742629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BD!MTB"
        threat_id = "2147742629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 e6 04 03 f2 33 d2 3d df 03 00 00 0f 44 ca 8b d7 c1 ea 05 03 95 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 03 cf 33 d1 33 d6 2b da 8b fb c1 e7 04 3d 93 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BD_2147742629_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BD!MTB"
        threat_id = "2147742629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b ce 49 8b c1 49 ff c3 48 f7 e6 48 8b c6 48 ff c6 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 ?? 48 [0-10] 48 2b c1 0f b6 44 [0-4] 41 30 43 ?? 49 ff c8 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BE_2147742741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BE!MTB"
        threat_id = "2147742741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c8 0b 98 7f b8 c6 ee 57 15 81 45 ?? be 6c ?? 28 81 e3 15 2d 0d 0f 81 6d ?? 36 18 c4 05 81 f3 26 ed 5f 56 81 45 ?? 40 b7 cb 5c 8b 5d ?? 8b 45 ?? 33 d6 2b 4d ?? 40 2b fa 89 4d ?? 89 45 ?? 3b 45 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BE_2147742741_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BE!MTB"
        threat_id = "2147742741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 50 50 44 41 54 41 [0-32] 25 73 5c 62 6f 78}  //weight: 1, accuracy: Low
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 64 6f 77 73 [0-80] 41 70 70 49 6e 69 74 5f 44 4c 4c 73 [0-32] 25 73 5c 62 6f 78 2e 6c 6e 6b}  //weight: 1, accuracy: Low
        $x_1_3 = {6c 61 75 6e 63 68 [0-32] 50 72 6f 67 72 61 6d 46 69 6c 65 73 [0-32] 64 72 6f 70 [0-32] 44 4c 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BE_2147742741_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BE!MTB"
        threat_id = "2147742741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 00 b4 00 69 00 b4 00 72 00 b4 00 74 00 b4 00 75 00 b4 00 61 00 b4 00 6c 00 b4 00 50 00 b4 00 72 00 b4 00 6f 00 b4 00 74 00 b4 00 65 00 b4 00 63 00 b4 00 74 00 b4}  //weight: 1, accuracy: High
        $x_1_2 = "V%i%r%t%u%a%l%A%l%l%o%c%E%x%" wide //weight: 1
        $x_1_3 = {47 00 5e 00 65 00 5e 00 74 00 5e 00 54 00 5e 00 69 00 5e 00 63 00 5e 00 6b 00 5e 00 43 00 5e 00 6f 00 5e 00 75 00 5e 00 6e 00 5e 00 74 00 5e}  //weight: 1, accuracy: High
        $x_1_4 = "M@i@c@r@o@s@o@f@t@" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BG_2147742795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BG!MTB"
        threat_id = "2147742795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hackeRLO_project\\Projet_2\\project\\hackerlo\\Release\\hackerlo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BG_2147742795_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BG!MTB"
        threat_id = "2147742795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 55 10 8b 45 10 8a 92 85 c5 0a 00 88 14 01}  //weight: 1, accuracy: High
        $x_2_2 = {d3 ea 89 55 e0 8b 45 e0 03 45 a8 89 45 e0 8b 4d ec 33 4d b8 89 4d ec 81 3d ?? ?? ?? ?? c1 10 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BH_2147742859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BH!MTB"
        threat_id = "2147742859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You are fucking AV vendors!" ascii //weight: 1
        $x_1_2 = "kicking guys" ascii //weight: 1
        $x_1_3 = "You are my sunshine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BH_2147742859_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BH!MTB"
        threat_id = "2147742859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 d0 f7 ff ff 03 85 ?? ?? ?? ?? 89 85 d0 f7 ff ff 8b ?? d4 f7 ff ff 33 ?? b8 f7 ff ff 89 ?? d4 f7 ff ff 8b ?? d4 f7 ff ff 33 ?? d0 f7 ff ff 89 ?? d0 f7 ff ff 8b ?? cc f7 ff ff 2b ?? d0 f7 ff ff 89 85 cc f7 ff ff 8b ?? cc f7 ff ff c1 ?? 04 89 ?? d4 f7 ff ff 81 3d ?? ?? ?? ?? 93 04 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BI_2147742860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BI!MTB"
        threat_id = "2147742860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c8 0b 98 7f b8 c6 ee 57 15 81 45 ?? be 6c ?? 28 81 e3 15 2d 0d 0f 81 6d ?? 36 18 c4 05 81 f3 26 ed 5f 56 81 45 ?? 40 b7 cb 5c a1 ?? ?? ?? ?? 8b 5d ?? 33 f2 3d 9b 04 00 00 75 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BI_2147742860_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BI!MTB"
        threat_id = "2147742860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f6 da 32 c2 d2 fc 80 c2 e0 0f bb d0 80 f2 75 66 35 bd 0d 66 81 fa ce 01 c1 f8 88 32 da c0 e4 8c 12 c0 d3 e8 89 0c 14 f9 8b 07 8d bf 04 00 00 00 e9}  //weight: 2, accuracy: High
        $x_2_2 = {f7 da 42 81 f2 81 3a eb 41 d1 ca 66 f7 c1 8c 0b 80 fa 45 33 da f9 03 f2 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BI_2147742860_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BI!MTB"
        threat_id = "2147742860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "( $URL , $PATH ," ascii //weight: 10
        $x_10_2 = "( $TITLE , $BODY , $TYPE ," ascii //weight: 10
        $x_10_3 = "READRESOURCES ( $RESNAME , $RESTYPE )" ascii //weight: 10
        $x_10_4 = "( $FILE , $STARTUP , $RES , $RUN =" ascii //weight: 10
        $x_10_5 = "( $WPATH , $LPFILE , $PROTECT , $PERSIST" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PF_2147743106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PF!MTB"
        threat_id = "2147743106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff d6 33 d2 8b c7 f7 74 24 20 8b 44 24 14 8a 0c 50 30 0c 1f 47 3b fd 75 95}  //weight: 1, accuracy: High
        $x_1_2 = {56 8b 74 24 10 85 f6 76 13 8b 44 24 08 8b 4c 24 0c 2b c8 8a 14 01 88 10 40 4e 75 f7 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PF_2147743106_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PF!MTB"
        threat_id = "2147743106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {87 ff 8b 1c 0a 49 41 ?? ?? 81 f3 ?? ?? ?? ?? 49 41 87 ff 89 1c 08 49 41 ?? ?? 83 c1 04 49 41 c1 e9 00 81 f9 ?? ?? 00 00 75 d4 87 ff 49 41 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {87 ff 49 41 8b 1c 0a c1 e6 00 87 ff 81 f3 ?? ?? ?? ?? c1 e6 00 49 41 89 1c 08 c1 e6 00 87 ff 83 c1 04 c1 e6 00 ?? ?? 81 f9 ?? ?? 00 00 75 d1 49 41 c1 e6 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {87 ff 49 41 c1 e6 00 8b 1c 0a c1 e6 00 87 ff 81 f3 ?? ?? ?? ?? c1 e6 00 49 41 89 1c 08 c1 e6 00 87 ff 83 c1 04 c1 e6 00 ?? ?? 81 f9 ?? ?? 00 00 75 d0 49 41 c1 e6 00 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_BJ_2147743115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BJ!MTB"
        threat_id = "2147743115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PQRVW9" ascii //weight: 1
        $x_1_2 = "PQRVW=w" ascii //weight: 1
        $x_1_3 = "PQRVW;M" ascii //weight: 1
        $x_1_4 = "PQRVW;E" ascii //weight: 1
        $x_1_5 = "PQRVW;u" ascii //weight: 1
        $x_1_6 = "winspool.drv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BJ_2147743115_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BJ!MTB"
        threat_id = "2147743115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb 70 0a 00 00 75 ?? 56 56 56 56 ff 15 ?? ?? ?? ?? 56 56 56 56 56 56 ff 15 ?? ?? ?? ?? 56 8d 85 18 fb ff ff 50 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d 14 fb ff ff 30 04 39 81 fb 9b 0a 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BK_2147743116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BK!MTB"
        threat_id = "2147743116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 48 c0 00 00 01 85 d0 f3 ff ff 83 85 d0 f3 ff ff 7b 8b 85 d0 f3 ff ff 8a 4c 30 85 a1 ?? ?? ?? ?? 88 0c 06 81 3d ?? ?? ?? ?? cb 0c 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 6b fa 03 00 01 85 18 fe ff ff a1 ?? ?? ?? ?? 03 85 1c fe ff ff 8b 8d 18 fe ff ff 03 8d 1c fe ff ff 8a 09 88 08 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 8c 10 85 c5 0a 00 a1 ?? ?? ?? ?? 88 0c 10 42 a1 ?? ?? ?? ?? 3b d0 72 e2}  //weight: 1, accuracy: Low
        $x_1_4 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 1e 46 3b f7 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_BK_2147743116_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BK!MTB"
        threat_id = "2147743116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CASE WINGETTITLE ( \"AnVir\" & \" \" & \"Task\" & \" \" & \"Manager\" )" ascii //weight: 1
        $x_1_2 = "CASE PROCESSEXISTS ( \"procexp.exe\" )" ascii //weight: 1
        $x_1_3 = "CASE PROCESSEXISTS ( \"ProcessHacker.exe\" )" ascii //weight: 1
        $x_1_4 = "IF NOT FILEEXISTS ( \"C:\\ProgramData\\SystemNetwork\\\" ) THEN" ascii //weight: 1
        $x_1_5 = "DIRCREATE ( \"C:\\ProgramData\\SystemNetwork\" )" ascii //weight: 1
        $x_1_6 = "CASE PROCESSEXISTS ( \"taskmgr.exe\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MS_2147743118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MS!MTB"
        threat_id = "2147743118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 d8 2d 00 10 00 00 89 45 d8 c7 45 fc 00 00 00 00 83 e6 3b 2b f3 86 e9 83 fe 3a 8d bd d4 ff ff ff 03 1f ba 01 00 00 00 66 8b c3 83 f9 0f 33 c0 8b 4d d8 66 8b 01 3b 45 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MS_2147743118_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MS!MTB"
        threat_id = "2147743118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 83 c4 ?? 51 53 52 57 ff 75 ?? 58 85 c0 74 ?? 33 db 33 d2 bf ?? ?? ?? ?? b9 01 00 00 00 d1 c0 8a dc 8a e6 d1 cb 8b 4d ?? 4f 75 ?? c1 cb ?? 8b c3 5f 5a 5b 59 c9 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_J_2147743150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.J!MSR"
        threat_id = "2147743150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 89 45 f4 90 90 90 8b 45 c0 89 45 e4 90 90 90 90 90 8b 45 f4 01 45 e4 90 90 90 90 8b 45 e8 89 45 d8 90 90 90 90 8b 45 e4 89 45 dc 8b 45 d8 8a 80 5c ad 45 00 88 45 bf 90 c6 45 d3 71 90 90 90 8a 45 bf 32 45 d3 8b 55 dc 88 02 90 90 90 90 ff 45 e8 81 7d e8 ab 5d 00 00 75 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SS_2147743181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SS!MTB"
        threat_id = "2147743181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 89 45 f4 [0-16] 33 c0 [0-16] 8b d0 [0-16] 8b 5d f4 [0-16] 03 da [0-16] 8b d0 [0-16] 8b f3 [0-16] 8a 92 ?? ?? ?? 00 88 55 fb [0-16] b2 ?? [0-16] 32 55 fb [0-16] 88 16 [0-16] 40 3d ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc [0-16] 8b 7d fc ff 75 f8 01 3c 24 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AK_2147743288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AK!MTB"
        threat_id = "2147743288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 e8 fe ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 ?? ff ff ff 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 08 03 55 f0 0f b6 02 8b 4d fc 03 4d ec 0f b6 d1 0f b6 8c 15 ?? ?? ff ff 33 c1 8b 55 08 03 55 f0 88 02 e9 ?? ff ff ff 8b 4d e4 33 cd e8 ?? ?? ?? 00 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {45 33 c9 81 e5 ff 00 00 00 33 c0 8a 4c 2c 10 03 d9 81 e3 ff 00 00 00 8a 44 1c 10 88 44 2c 10 02 c1 25 ff 00 00 00 88 4c 1c 10 8a 0c 32 8a 44 04 10 32 c8 88 0c 32 42 3b d7 7c c5}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = "Decrypt" ascii //weight: 1
        $x_1_6 = "CryptAcquireContextA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_CryptInject_BL_2147743294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BL!MTB"
        threat_id = "2147743294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 81 ff 9b 0a 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 fd 43 03 00 05 c3 9e 26 00 81 3d ?? ?? ?? ?? ac 10 00 00 56 a3 ?? ?? ?? ?? 8b f0 75 ?? ff 15 ?? ?? ?? ?? 8b 4d ?? 8b c6 c1 e8 10 33 cd 25 ff 7f 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AL_2147743310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AL!MTB"
        threat_id = "2147743310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 8b c7 e8 ?? ?? ff ff 43 81 fb ?? ?? 00 00 75 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c8 03 ca [0-16] b0 ?? [0-16] 32 82 ?? ?? ?? 00 [0-16] 88 01 [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AM_2147743312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AM!MTB"
        threat_id = "2147743312"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 8b 55 08 89 11 8b 85 ?? ?? ff ff 83 c0 10 50 8b 4d fc 51 6a 00 e8 ?? ?? ?? ?? 83 c4 0c 8b 55 f8 52 ff 55 fc 83 c4 04 5f 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 03 45 08 8b 0d ?? ?? ?? 00 8a 14 08 32 15 ?? ?? ?? 00 8b 45 0c 03 45 08 8b 0d ?? ?? ?? 00 88 14 08 83 3d ?? ?? ?? 00 03 76 0b 8b 55 08 83 c2 01 89 55 08 eb 01 cc 81 7d 08 ?? ?? 00 00 7e 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PJ_2147743321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PJ!MTB"
        threat_id = "2147743321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Fuck Defender:))" ascii //weight: 1
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "CryptAcquireContextA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PJ_2147743321_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PJ!MTB"
        threat_id = "2147743321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 84 00 00 00 8b 4c 24 18 8b 54 24 10 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 74 24 18 c1 ee 05 03 74 24 7c 03 d8 03 d1 33 da 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 8c 24 84 00 00 00 8b 54 24 20 33 c0 a3 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 44 24 10 c1 ee 05 03 74 24 7c 03 d9 03 c2 33 d8 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 70 8b 44 24 14 8b 4c 24 0c 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 74 24 14 c1 ee 05 03 74 24 78 03 da 03 c8 33 d9 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b cf c1 e9 05 03 4c 24 70 33 c8 33 ce 29 4c 24 18 8b 44 24 74 29 44 24 10 83 6c 24 68 01 0f 85 ?? ?? ff ff 81 3d ?? ?? ?? ?? 61 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_5 = {8b d7 c1 ea 05 03 54 24 70 33 d0 33 d6 29 54 24 20 8b 44 24 74 29 44 24 10 83 6c 24 68 01 0f 85 ?? ?? ff ff 81 3d ?? ?? ?? ?? 61 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_6 = {8b cf c1 e9 05 03 4c 24 6c 33 c8 33 ce 29 4c 24 14 8b 84 24 84 00 00 00 29 44 24 0c 83 6c 24 64 01 0f 85 ?? ?? ff ff 81 3d ?? ?? ?? ?? 61 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_CryptInject_PJ_2147743321_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PJ!MTB"
        threat_id = "2147743321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "schtasks /create /tn area41 /tr C:\\_Microsoft\\Microsoft.exe /sc minute /mo 1" wide //weight: 1
        $x_1_3 = "autorun.inf" wide //weight: 1
        $x_1_4 = {5c 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 6f 00 20 00 6a 00 6f 00 67 00 6f 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 [0-32] 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 70 72 6f 6a 65 63 74 6f 20 6a 6f 67 6f 5c 53 79 73 74 65 6d 33 32 5c 53 79 73 74 65 6d 33 32 5c [0-32] 5c 53 79 73 74 65 6d 33 32 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_CryptInject_L_2147743467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.L"
        threat_id = "2147743467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Start Menu\\Programs\\Startup\\Windows.LNK" ascii //weight: 1
        $x_1_2 = "Test_Folder\\Resources" ascii //weight: 1
        $x_1_3 = "It's Good" ascii //weight: 1
        $x_1_4 = "Temp_Test.tester" ascii //weight: 1
        $x_1_5 = "C:\\Users\\lenovo\\source\\repos\\Junk_Code_Lost_Files" ascii //weight: 1
        $x_1_6 = "Donald Trumps Hair Line" wide //weight: 1
        $x_1_7 = "SecurityUpdater.exe.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_CryptInject_BP_2147743495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BP!MTB"
        threat_id = "2147743495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ping 127.0.0.1 > nul" wide //weight: 1
        $x_1_2 = "echo j | del Trinity.bat" wide //weight: 1
        $x_1_3 = "TrinityObfuscator" ascii //weight: 1
        $x_1_4 = "ILoveTheRealGiths" ascii //weight: 1
        $x_1_5 = "file_exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BP_2147743495_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BP!MTB"
        threat_id = "2147743495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 75 f8 03 75 f0 68 5c 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 8b 55 f8 03 55 f0 8b 45 fc 8b 4d f4 8a 0c 31 88 0c 10 8b 55 f8 83 c2 01 89 55 f8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BO_2147743499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BO!MTB"
        threat_id = "2147743499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 03 2b 55 d4 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 03 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 65 fc a1 ?? ?? ?? ?? 58 8b e8 a1 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? ff 25 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AO_2147743539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AO!MTB"
        threat_id = "2147743539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 8d 84 02 ?? ?? 00 00 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 ?? ?? 00 00 8b 55 08 89 0a 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3 4f 00 b8 ?? ?? ?? 00 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AP_2147743609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AP!MTB"
        threat_id = "2147743609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b fe 88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34 78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6 44 24 41 33 c6 44 24 43 34 c6 44 24 44 74 88 54 24 46 c6 44 24 40 43 c6 44 24 39 62}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AP_2147743609_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AP!MTB"
        threat_id = "2147743609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 33 f6 85 d2 7e 0d e8 ?? ?? ff ff 30 04 0e 46 3b f2 7c f3 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 10 25 ff 7f 00 00 c3 4f 00 69 05 ?? ?? ?? 00 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? 00 c1 e8 10 25 ff 7f 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_A_2147743738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.A!MTB"
        threat_id = "2147743738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 00 81 6d fc ?? ?? ?? ?? 81 45 fc ?? ?? ?? ?? c1 e8 ?? 81 6d fc ?? ?? ?? ?? c1 e0 ?? 81 45 fc ?? ?? ?? ?? b8 ?? ?? ?? ?? 81 6d fc ?? ?? ?? ?? 35 ?? ?? ?? ?? 81 45 fc ?? ?? ?? ?? c1 eb ?? 81 45 fc ?? ?? ?? ?? d1 e3 d1 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_A_2147743738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.A!MTB"
        threat_id = "2147743738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 82 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 83 ?? ?? ?? ?? 03 c1 83 e0 0f 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 c1 05 81 f9 00 66 0d 00 72}  //weight: 1, accuracy: Low
        $x_1_2 = "runDllFromMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PDSK_2147743910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PDSK!MTB"
        threat_id = "2147743910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 fd 8a 55 ff 0a c7 8b 5d e8 88 45 fd 88 14 1e 8a 55 fe c7 05 ?? ?? ?? ?? 00 00 00 00 88 54 1e 01 81 3d ?? ?? ?? ?? d8 01 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_VDSK_2147743914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.VDSK!MTB"
        threat_id = "2147743914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f4 8b cb c1 e9 05 03 c3 03 4d e8 33 c8 c7 05 ?? ?? ?? ?? f4 6e e0 f7 33 4d fc 2b f9 81 fe d9 02 00 00 75 23}  //weight: 2, accuracy: Low
        $x_2_2 = {88 54 24 11 8a d6 80 e2 f0 88 74 24 10 c0 e2 02 0a 14 18 88 54 24 12 8a d6 80 e2 fc c0 e2 04 0a 54 18 01 88 54 24 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_PVD_2147744026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PVD!MTB"
        threat_id = "2147744026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 14 19 88 14 38 8a 83 ?? ?? ?? ?? 84 c0 75 ?? a1 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 03 c3 03 c7 30 08 83 3d ?? ?? ?? ?? 03 76}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 44 24 10 6a 24 33 d2 5f 8d 0c 06 8b c6 f7 f7 8b 44 24 0c 8a 04 02 30 01 46 3b 74 24 14 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_PVDS_2147744027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PVDS!MTB"
        threat_id = "2147744027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 01 8b 74 24 1c 81 f6 a6 77 2b 37 8b 7c 24 08 88 14 07 01 f0 8b 74 24 10 39 f0 89 44 24 04 74}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 dc c6 45 ef a8 8b 4d e4 8a 14 01 8b 75 e0 88 14 06 83 c0 01 c7 45 f0 d9 29 9a 95 8b 7d e8 39 f8 89 45 dc 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_MM_2147744029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MM!MTB"
        threat_id = "2147744029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 95 fa fb ff ff 83 c3 04 88 54 3e 02 83 c6 03 8b 0d ?? ?? ?? ?? 3b d9}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 89 0d ?? ?? ?? ?? c1 e8 10 30 04 13 43 3b df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AR_2147744072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AR!MTB"
        threat_id = "2147744072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 83 c1 01 89 4d fc 81 7d fc ?? ?? 00 00 73 2a 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 f0 0f be 0c 10 8b 55 fc 0f b6 82 00 50 44 00 33 c1 8b 4d fc 88 81 00 50 44 00 eb c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AR_2147744072_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AR!MTB"
        threat_id = "2147744072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "( \"0x0x446c6c43616c6c28226b65726e656c3332222c2022707472222c20225669727475616c416c6c6f63222c202264776f7264222c" ascii //weight: 10
        $x_10_2 = "= EXECUTE ( BINARYTOSTRING ( \"0x4465634461746128223078363737433733373637383434364237" ascii //weight: 10
        $x_5_3 = "( \"0x40486f6d654472697665202620225c5c5c5c57696e646f77735c5c5c5c4d6963726f736f66742e4e45" ascii //weight: 5
        $x_5_4 = "( \"545c5c5c5c4672616d65776f726b5c5c5c5c76322e302e35303732375c5c5c5c526567537663732e65786522" ascii //weight: 5
        $x_5_5 = "( \"545c5c5c5c4672616d65776f726b5c5c5c5c76342e302e33303331395c5c5c5c526567537663732e65786522" wide //weight: 5
        $x_1_6 = "( \"0x4053637269707446756c6c50617468\" )" ascii //weight: 1
        $x_1_7 = "( \"0x4053797374656d446972202620225c6578706c6f7265722e65786522\" )" ascii //weight: 1
        $x_1_8 = "( \"0x4053797374656d446972202620225c737663686f73742e65786522\" )" ascii //weight: 1
        $x_1_9 = "( \"0x4053797374656d446972202620225c646c6c686f73742e65786522\" )" ascii //weight: 1
        $x_1_10 = "( \"0x4053797374656d446972202620225c636d642e65786522\" )" ascii //weight: 1
        $x_1_11 = "( \"0x62696E617279746F737472696E67\" , \"0x4C\"" ascii //weight: 1
        $x_1_12 = "= STRINGSPLIT (" ascii //weight: 1
        $x_1_13 = "= EXECUTE (" ascii //weight: 1
        $x_1_14 = "SLEEP ( " ascii //weight: 1
        $x_1_15 = "( \"4054656D70446972\" ) ," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_AS_2147744073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AS!MTB"
        threat_id = "2147744073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\avgSP_Open" wide //weight: 1
        $x_1_2 = {31 ca 59 8a 0c 10 5a 84 c9 75 12 8b 0d ?? ?? ?? ?? 8a 1d ?? ?? ?? ?? 03 c8 03 cf 30 19 39 15 ?? ?? ?? ?? 76 03 40 eb 01 cb}  //weight: 1, accuracy: Low
        $x_1_3 = {03 d9 03 c8 46 8a 1c 03 88 1c 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AS_2147744073_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AS!MTB"
        threat_id = "2147744073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 40 89 45 ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 73 ?? a1 ?? ?? ?? ?? 89 45 ?? b8 ?? ?? ?? ?? 01 45 ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 4d ?? 03 4d ?? 8a 09 88 08 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b c1 c1 e8 10 30 04 1e 46 3b f7 7c e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AS_2147744073_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AS!MTB"
        threat_id = "2147744073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 13 43 3b df 7c 4f 00 81 ff ?? ?? 00 00 75 13 56 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 95 ?? ?? ff ff 69 c9 ?? ?? ?? 00 81 c1 ?? ?? ?? 00 8b c1 89 0d ?? ?? ?? 00 c1 e8 10 30 04 13 43 3b df 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 1f 47 3b fe 7c 4f 00 81 fe ?? ?? 00 00 75 0e 6a 00 ff 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 69 c9 ?? ?? ?? 00 81 c1 ?? ?? ?? 00 8b c1 89 0d ?? ?? ?? 00 c1 e8 10 30 04 1f 47 3b fe 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_S_2147744103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.S!MSR"
        threat_id = "2147744103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eyybc.com/forumdisplay.php?fid=17/memcp.php/ip.asp/time.asp/gonggao.txt/ec-user6.php/ec-bd.php/ec-jh.php" ascii //weight: 1
        $x_1_2 = "_EL_HideOwner" ascii //weight: 1
        $x_1_3 = "C:\\Tomato\\Setup.to" wide //weight: 1
        $x_1_4 = "\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "0C28D4271B91F340C4177F36C0ED07BB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PVS_2147744124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PVS!MTB"
        threat_id = "2147744124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 04 33 33 c8 2b f9 8b cf 8b c7 c1 e9 05 03 0d ?? ?? ?? ?? c1 e0 04 03 05 ?? ?? ?? ?? 33 c8 8d 04 3b 2b 5c 24 10 33 c8 2b f1 45 83 fd 20 72}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 4c 18 03 8a e9 88 4d ff 80 e5 f0 8a d1 80 e2 fc c0 e5 02 0a 2c 18 c0 e2 04 0a 54 18 01 83 3d ?? ?? ?? ?? 2c 88 6d fe 88 55 fd 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_PA_2147744248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PA!MTB"
        threat_id = "2147744248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 f9 1f 8b d1 33 c8 33 d6 3b ca 7f 22 8b 4d 0c 8b 09 8b 51 0c 8b 71 14 2b d6 8a 0c 02 8d 34 02 8b d0 33 cb 83 e2 20 33 ca 03 c7 88 0e eb cc 03 00 8b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BZ_2147744324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BZ!MTB"
        threat_id = "2147744324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 06 33 c9 8a 4d 11 32 c8 51 56 8d 4d f0 e8 ?? ?? ?? ?? 8b 45 f0 b9 ?? ?? ?? ?? 66 0f b6 04 06 03 45 10 69 c0 93 31 00 00 2b c8 8b 45 0c 46 89 4d 10 3b 70 f8 7c c8}  //weight: 1, accuracy: Low
        $x_1_2 = "set PASSWD='" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BZ_2147744324_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BZ!MTB"
        threat_id = "2147744324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 8c 30 3b 2d 0b 00 8b 15 ?? ?? ?? ?? 88 0c 32 81 3d ?? ?? ?? ?? 37 0d 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 d3 e0 8b cf c1 e9 05 03 4d e4 03 45 d8 89 15 ?? ?? ?? ?? 33 c1 8b 4d f0 03 cf 33 c1 29 45 f8 a1 ?? ?? ?? ?? 3d d5 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SK_2147744366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SK!MSR"
        threat_id = "2147744366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sexorbit" wide //weight: 1
        $x_1_2 = "barrowdestill" wide //weight: 1
        $x_1_3 = "jrATTA.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AJ_2147744481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AJ!MSR"
        threat_id = "2147744481"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nrpudmvndlivebth" ascii //weight: 1
        $x_1_2 = "TrackPopupMenu" ascii //weight: 1
        $x_1_3 = "c:\\temp\\AutoWallpaper.bmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PVK_2147744772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PVK!MTB"
        threat_id = "2147744772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 30 01 8b 75 10 c0 e9 04 c0 e2 04 0a ca 88 4d ff eb}  //weight: 2, accuracy: High
        $x_2_2 = {8a 55 ff 47 d0 e2 83 ff 08 89 7d ec 88 55 ff 0f 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CB_2147744837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CB!MTB"
        threat_id = "2147744837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fb 69 04 00 00 75 17 56 ff 15 ?? ?? ?? ?? 56 56 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 30 04 39}  //weight: 1, accuracy: Low
        $x_1_2 = {05 f5 d0 00 00 a3 ?? ?? ?? ?? 33 ff 3d f5 0b 00 00 75 0e 8d 45 ?? 50 56 56 56 ff d3 a1 ?? ?? ?? ?? 81 ff aa c2 5f 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CB_2147744837_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CB!MTB"
        threat_id = "2147744837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c3 8b d3 83 e0 03 c1 ea 02 43 8d 3c 82 8b 54 96 18 8d 0c c5 00 00 00 00 b8 ff 00 00 00 d3 e0 23 d0 d3 ea 30 14 37 83 fb 10 7c d4}  //weight: 1, accuracy: High
        $x_1_2 = {32 c0 32 5d ea 32 5d eb 32 d8 8a 46 f8 88 5f fc 84 c0 74 26}  //weight: 1, accuracy: High
        $x_1_3 = {8b c2 8b ca c1 e8 02 83 e1 03 03 c6 8a 04 88 88 04 17 42 83 fa 10 72 e8}  //weight: 1, accuracy: High
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "GetTickCount64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_VDS_2147744915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.VDS!MTB"
        threat_id = "2147744915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 24 12 08 5c 24 10 8a c2 83 25 ?? ?? ?? ?? 00 24 fc c0 e0 04 0a f8 81 3d ?? ?? ?? ?? 38 13 00 00 88 7c 24 13 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 dc 8d 3c 10 8a 07 32 c1 39 5d c8 74 ?? 88 07 eb ?? 88 17}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 4c 24 18 8b d0 d3 e2 8b c8 c1 e9 05 03 4c 24 24 03 54 24 28 c7 05 ?? ?? ?? ?? 00 00 00 00 33 d1 8b 4c 24 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_DSKP_2147744954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DSKP!MTB"
        threat_id = "2147744954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d e9 2b 00 00 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 e9 2b 00 00 a1 ?? ?? ?? ?? a3}  //weight: 2, accuracy: Low
        $x_2_2 = {8b ca 2b ce 83 e9 4b 8b f9 6b ff 53 81 c5 2c c6 14 01 03 d2 2b d7 8b 7c 24 18 89 2b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_AT_2147745048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AT!MTB"
        threat_id = "2147745048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VirtualAlloc" ascii //weight: 1
        $x_1_2 = "DecodePointer" ascii //weight: 1
        $x_1_3 = "ReadEncryptedFileRaw" ascii //weight: 1
        $x_1_4 = {c7 44 24 08 00 10 00 00 c7 44 24 0c 40 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {88 44 24 4f 8b 44 24 30 8b 4c 24 08 8a 1c 08 8b 44 24 28 32 1c 10 8b 54 24 2c 88 1c 0a 83 c1 01 8b 44 24 34 39 c1 8b 44 24 04 89 4c 24 1c 89 44 24 20 89 7c 24 24 0f 84 ?? ff ff ff e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_6 = {0f b6 c9 8b 74 24 34 8b 7c 24 14 89 0c 24 8a 0c 3e 8b 34 24 01 de 81 e6 ff 00 00 00 8b 5c 24 2c 32 0c 33 8b 74 24 30 88 0c 3e 83 c7 01 8b 4c 24 38 39 cf 8b 4c 24 08 89 4c 24 1c 89 54 24 18 89 7c 24 20 0f 84 ?? ff ff ff e9 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_CryptInject_CC_2147745086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CC!MTB"
        threat_id = "2147745086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 36 9c 97 01 7c ?? eb ?? 81 3d ?? ?? ?? ?? 1e 07 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {9c 4e 7f 46 75 ?? ?? 81 ?? 16 6d b0 2e 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AU_2147745137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AU!MTB"
        threat_id = "2147745137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Interface\\{b196b287-bab4-101a-b69c-00aa00341d07}" wide //weight: 1
        $x_1_2 = {55 8b ec 83 ec 08 56 8b 15 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 8f 45 f8 8b 75 f8 33 f2 8b d6 8b ca b8 ?? ?? ?? ?? 03 c1 2d ?? ?? ?? ?? 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {0f be 04 30 f7 d8 8b 4d f8 0f be 11 2b d0 8b 45 f8 88 10 5e 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PB_2147745227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PB!MTB"
        threat_id = "2147745227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 8a 10 00 00 8b 45 08 89 10 8b 4d 08 8b 11 81 ea 8a 10 00 00 8b 45 08 89 10 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 57 [0-32] 8b 0d ?? ?? ?? ?? 8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? [0-32] a3 ?? ?? ?? ?? 8b ff [0-64] 8b ca 00 02 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CD_2147745237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CD!MTB"
        threat_id = "2147745237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/sochvst.bat" ascii //weight: 1
        $x_1_2 = "HEBECA@CHINA.COM" ascii //weight: 1
        $x_1_3 = "DisableThreadLibraryCalls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CD_2147745237_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CD!MTB"
        threat_id = "2147745237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 08 81 f9 d0 a6 8f 34 75 08 40 3d aa 8f e0 14 7c e9}  //weight: 1, accuracy: High
        $x_1_2 = {81 fe 01 3f 14 22 7c cd a1 ?? ?? ?? ?? 8b f7 05 3b 2d 0b 00 a3 ?? ?? ?? ?? 81 fe 89 62 65 00 75 10 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 46 81 fe 56 d0 66 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_PDS_2147745263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PDS!MTB"
        threat_id = "2147745263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 d8 69 c0 7b 0f 01 00 8a 0d ?? ?? ?? ?? a3 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 ec 30 4a 04 03 c2 83 e0 03 0f b6 44 05 f4 30 42 05 81 fe e2 02 00 00 72}  //weight: 2, accuracy: High
        $x_2_3 = {0f b6 c0 66 8b d0 66 c1 e2 04 66 2b d0 8b c6 f7 d8 66 c1 e2 02 66 2b c2 66 03 f8 8b 44 24 10 66 89 3d 07 00 66 8b 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_SC_2147745551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SC!MSR"
        threat_id = "2147745551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getnameinfo" ascii //weight: 1
        $x_1_2 = "zipcrypt" ascii //weight: 1
        $x_1_3 = "fakecrc32" ascii //weight: 1
        $x_1_4 = "enables Data collection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PC_2147745629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PC!MTB"
        threat_id = "2147745629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? 00 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c 08 00 81 ff ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 69 c0 fd 43 03 00 56 a3 ?? ?? ?? 00 81 05 ?? ?? ?? 00 c3 9e 26 00 81 3d ?? ?? ?? 00 ?? ?? 00 00 0f b7 35 ?? ?? ?? 00 75 ?? 6a 00 6a 00 ff 15 ?? ?? ?? 00 8b c6 25 ff 7f 00 00 5e c3 0c 00 81 3d ?? ?? ?? 00 ?? ?? 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AB_2147745778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AB!MSR"
        threat_id = "2147745778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dEmb5MVcmG2uB4Ew34nx0eoXjqToQ4meSTO3a0" ascii //weight: 1
        $x_1_2 = "kM8PoAQRAoasHjP4JNmK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PD_2147745812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PD!MTB"
        threat_id = "2147745812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 95 00 ff ff ff 88 55 e3 0f be 45 ef 83 e0 0f c1 e0 04 0f be 4d e3 83 e1 0f 0b c1 8b 55 0c 03 55 c8 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PD_2147745812_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PD!MTB"
        threat_id = "2147745812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 fe ab 4e 19 00 75 06 ff 15 ?? ?? ?? 00 46 81 fe 46 ed 54 00 7c dd 8b 4d fc 5f 5e 33 cd 5b e8 ?? 00 00 00 8b e5 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {12 0f 00 00 75 08 6a 00 ff 15 ?? ?? ?? 00 [0-5] 00 69 ?? fd 43 03 00 [0-5] 00 81 05 ?? ?? ?? 00 c3 9e 26 00 81 3d ?? ?? ?? 00 cf 12 00 00 0f b7 ?? ?? ?? ?? 00 75 0a 6a 00 6a 00 ff 15 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_1_3 = {81 ff 69 04 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? 00 6a 00 6a 00 [0-8] ff 15 ?? ?? ?? 00 [0-112] 30 ?? ?? 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_N_2147746208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.N!MSR"
        threat_id = "2147746208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 f3 6a 00 89 3c 24 33 ff 03 fb 8b c7 5f aa 49 75 c4}  //weight: 1, accuracy: High
        $x_1_2 = {2b 14 24 03 55 f8 83 e0 00 03 c2 5a 0f b6 1c 30 57 33 3c 24 03 7d f0 83 e2 00 0b d7 5f d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d f4 75 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_PE_2147747866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PE!MTB"
        threat_id = "2147747866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b c1 6a 14 5e f7 f6 8a 44 15 ?? 30 81 ?? ?? ?? 00 41 81 f9 00 50 00 00 72 e4 33 d2 5e 33 c9 3b ca 8d 41 01 0f 45 c1 8d 48 01 81 f9 88 13 00 00 7c ed 42 81 fa e0 93 04 00 7c e2}  //weight: 10, accuracy: Low
        $x_1_2 = {33 c9 3b ca 8d 41 01 0f 45 c1 8d 48 01 81 f9 ?? ?? 00 00 7c ?? 42 81 fa ?? ?? ?? 00 7c ?? 33 c9 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_2147747998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MT!MTB"
        threat_id = "2147747998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 13 4c 4c 4c 4c 89 ?? 24 4c 4c 4c 4c 89 ?? 24 4c 4c 4c 4c 89 ?? 24 89 ?? 89 ?? 89 [0-10] f7 ?? 09 ?? 21 ?? 89 ?? 8b ?? 24 44 44 44 44 8b ?? 24 44 44 44 44 8b ?? 24 44 44 44 44 89 13 43 43 43 43 49 49 49 49 81 f9 ?? ?? ?? ?? 0f 85}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 13 4c 4c 4c 4c 89 ?? 24 4c 4c 4c 4c 89 ?? 24 4c 4c 4c 4c 89 ?? 24 89 ?? 89 ?? 89 ?? f7 ?? 21 ?? f7 ?? ?? ?? 21 ?? 09 ?? 89 ?? 89 ?? 8b ?? 24 44 44 44 44 8b ?? 24 44 44 44 44 8b ?? 24 44 44 44 44 89 13 43 43 43 43 49 49 49 49 81 f9 ?? ?? ?? ?? 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_SF_2147748096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SF!MSR"
        threat_id = "2147748096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Documents\\Visual Studio 2015\\Projects\\BaseLoader\\Release\\BaseLoader.pdb" ascii //weight: 1
        $x_1_2 = "Hack activated" ascii //weight: 1
        $x_1_3 = "http://tf2hack.com/dashboard" ascii //weight: 1
        $x_1_4 = "\\.\\pipe\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AC_2147748733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AC!MSR"
        threat_id = "2147748733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sign Fncdcget" wide //weight: 1
        $x_1_2 = "CreationPathological" wide //weight: 1
        $x_1_3 = "OrdinarySoft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AX_2147749245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AX!MTB"
        threat_id = "2147749245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Downloads\\svhost.exe" ascii //weight: 1
        $x_1_2 = {66 90 80 34 38 46 40 3b c6 7c f7}  //weight: 1, accuracy: High
        $x_1_3 = {8b c1 83 e0 01 8a 84 05 ?? ?? ff ff 30 04 39 41 3b ce 7c ec}  //weight: 1, accuracy: Low
        $x_1_4 = "\\support_cript\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_O_2147749991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.O!MSR"
        threat_id = "2147749991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FRyka.exe" wide //weight: 1
        $x_1_2 = {47 4f 66 66 69 63 01 00}  //weight: 1, accuracy: Low
        $x_1_3 = "EVENT_SINK_QueryInterface" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SK_2147750788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SK!MTB"
        threat_id = "2147750788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "307835333734373236393645363735323635373636353732373336353238323436343239" ascii //weight: 1
        $x_1_2 = "30783434364336433533373437323735363337343433373236353631373436353238323236323739373436353230" ascii //weight: 1
        $x_1_3 = "0x40486f6d654472697665202620225c5c5c5c57696e646f77735c5c5c5c4d6963726f736f66742e4e45545c5c5c5c4672616d65776f726b5c5c5c5c" ascii //weight: 1
        $x_1_4 = "( $URL , $PATH )" ascii //weight: 1
        $x_1_5 = "= STRINGREPLACE ( " ascii //weight: 1
        $x_2_6 = "( $FILE , $STARTUP , $RES , $RUN =" ascii //weight: 2
        $x_1_7 = "3078343636393643363534463730363536453238" ascii //weight: 1
        $x_1_8 = "= \"WriteProcessMemory" ascii //weight: 1
        $x_1_9 = "= STRINGREGEXPREPLACE ( $SITEM , \"^Row\\s\\d+\\|(.*)$\" , \"$1\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PG_2147751001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PG!MTB"
        threat_id = "2147751001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 71 68 00 00 8b f9 43 ff 71 00 46 8b f3 03 f8 8b fa 5b 8b f9 81 c6 ?? ?? ?? ?? 81 f3 da 00 00 00 81 c7 ?? ?? ?? ?? 03 f9 be ?? ?? ?? ?? 53 be ?? ?? 00 00 8b f0 4e 47 4f 8f 40 00 03 d9 81 eb ?? ?? 00 00 81 c7 ?? ?? 00 00 41 4e 8b f1 46 8b f3 40 81 eb ?? ?? ?? ?? 4e 43 03 f8 8b f1 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AD_2147751130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AD!MTB"
        threat_id = "2147751130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cover\\thousand\\Mean\\Death\\Build\\Reach\\Believe\\coastdraw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AE_2147751471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AE!MTB"
        threat_id = "2147751471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Administrator\\Documents\\Visual Studio 2005\\Projects\\Bomber2\\release\\Bomber2.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PI_2147751538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PI!MTB"
        threat_id = "2147751538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://install.xxxtoolbar.com/download_straight.html" wide //weight: 1
        $x_1_2 = "goicfboogidikkejccmclpieicihhlpo bihgbp" ascii //weight: 1
        $x_1_3 = "goicfboogidikkejccmclpieicihhlpo ejemdn" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\xxxtoolbar.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PI_2147751538_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PI!MTB"
        threat_id = "2147751538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 8b 02 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 e9 fc 1a 01 00 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 81 c1 fc 1a 01 00 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 00 03 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 [0-160] 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3}  //weight: 10, accuracy: Low
        $x_10_2 = {55 8b ec 53 57 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 02 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 00 03 a1 ?? ?? ?? ?? 33 c1 00 03 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 10, accuracy: Low
        $x_1_3 = {8b 4d fc 8d 94 01 36 a6 06 00 8b 45 08 03 10 8b 4d 08 89 11 8b 55 08 8b 02 2d 36 a6 06 00 8b 4d 08 89 01}  //weight: 1, accuracy: High
        $x_1_4 = {8b 55 08 03 32 8b 45 08 89 30 8b 4d 08 8b 11 81 ea 36 a6 06 00 8b 45 08 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_PH_2147751608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PH!MTB"
        threat_id = "2147751608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 8b 6c 24 1c 8b d7 2b ef 8d 04 2a 83 e0 3f 8a 80 ?? ?? ?? ?? 32 44 0b 04 41 88 02 42 3b ce 72}  //weight: 4, accuracy: Low
        $x_1_2 = {8b c1 99 f7 7c 24 20 8a 04 2a 8a 54 0f 08 32 c2 88 04 19 41 3b ce 7c e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PH_2147751608_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PH!MTB"
        threat_id = "2147751608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FILEINSTALL ( \"encrypted.bin\" , @TEMPDIR & \"\\1.resource\" , 1 )" ascii //weight: 1
        $x_1_2 = {5f 00 52 00 55 00 4e 00 50 00 45 00 20 00 28 00 20 00 46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 20 00 28 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 31 00 2e 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 22 00 20 00 29 00 20 00 2c 00 20 00 40 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 52 55 4e 50 45 20 28 20 46 49 4c 45 52 45 41 44 20 28 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 31 2e 72 65 73 6f 75 72 63 65 22 20 29 20 2c 20 40 57 49 4e 44 4f 57 53 44 49 52 20 26 20 22 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c [0-32] 5c 76 62 63 2e 65 78 65 22 20 29}  //weight: 1, accuracy: Low
        $x_1_4 = "REGWRITE ( STRINGREPLACE ( \"HKEY_CURRENTxentVersion\\Run\" , \"x\" , \"_USER\\Software\\Microsoft\\Windows\\Curr\" ) , \"Startup Name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CryptInject_AF_2147751972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AF!MTB"
        threat_id = "2147751972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hot\\work\\throw\\hot\\Log\\Oftenrepresent.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AQ_2147753335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AQ!MTB"
        threat_id = "2147753335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 01 00 00 00 33 f6 3b b5 3c ff ff ff 7f ?? 8b 57 0c 8b 4f 14 2b d1 89 5d e4 66 0f b6 0c 32 03 d6 8b d9 2b 4d e4 66 85 c9 7d 06 81 c1 00 01 00 00 88 0a 03 f0 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 01 00 00 00 33 ff 3b bd 34 ff ff ff 7f ?? 8b 4e 0c 8b 56 14 2b ca 89 5d e4 8d 14 39 66 0f b6 0c 39 8b d9 2b 4d e4 66 85 c9 7d 06 81 c1 00 01 00 00 88 0a 03 f8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SBR_2147753561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SBR!MSR"
        threat_id = "2147753561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sexbomb" ascii //weight: 1
        $x_1_2 = "Nedriven" ascii //weight: 1
        $x_1_3 = "Overskrivfunktion" ascii //weight: 1
        $x_1_4 = "string spa" wide //weight: 1
        $x_1_5 = "Saliency" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SBR_2147753561_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SBR!MSR"
        threat_id = "2147753561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bGjuhkbJxo|kxbj}mbzkyz4hgz" ascii //weight: 1
        $x_1_2 = "Request sent" ascii //weight: 1
        $x_1_3 = "userprofile" ascii //weight: 1
        $x_1_4 = "orderme/%s" ascii //weight: 1
        $x_1_5 = "Documents and Settings\\Administrator\\Adobe\\Driver\\dwg\\pid.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SBR_2147753561_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SBR!MSR"
        threat_id = "2147753561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\TEMP\\nso28AE.tmp" wide //weight: 1
        $x_1_2 = "bushwhackers" wide //weight: 1
        $x_1_3 = "currency.xml" wide //weight: 1
        $x_1_4 = "Pentagon.dll" wide //weight: 1
        $x_1_5 = "sitefiles" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SBR_2147753561_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SBR!MSR"
        threat_id = "2147753561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pipeline blacklisted" ascii //weight: 1
        $x_1_2 = "Server %s is blacklisted" ascii //weight: 1
        $x_1_3 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_4 = "Cookie File" ascii //weight: 1
        $x_1_5 = "user + domain + host name" ascii //weight: 1
        $x_1_6 = "mac\":\"%s\",\"channel\":\"%s\",\"sys\":\"%s" ascii //weight: 1
        $x_1_7 = "QmServer.pdb" ascii //weight: 1
        $x_1_8 = {43 3a 5c 54 45 4d 50 5c [0-16] 2e 69 6e 69}  //weight: 1, accuracy: Low
        $x_2_9 = "http://union.juzizm.com/api/live/server" ascii //weight: 2
        $x_2_10 = "union.xz345.cn" ascii //weight: 2
        $x_2_11 = "dh875.cn" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_SBR_2147753561_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SBR!MSR"
        threat_id = "2147753561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 74 74 70 3a 2f 2f 64 6f 77 6e 2e [0-48] 3a 38 38 38 38 2f 6f 6b 2e 74 78 74}  //weight: 2, accuracy: Low
        $x_2_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 6d 00 69 00 2e 00 [0-48] 3a 00 38 00 38 00 38 00 38 00 2f 00 6b 00 69 00 6c 00 6c 00 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 2, accuracy: Low
        $x_1_3 = "\\\\.\\root\\subscription" wide //weight: 1
        $x_1_4 = "fuckyoumm2_filter" wide //weight: 1
        $x_1_5 = "select * from __timerevent where timerid=\"fuckyoumm2_itimer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_AG_2147754027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AG!MTB"
        threat_id = "2147754027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rise\\Window\\position\\Character\\opposite\\Miss\\lawCome.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AG_2147754027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AG!MTB"
        threat_id = "2147754027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\Intel\\RuntimeBroker.exe" wide //weight: 1
        $x_1_2 = "\\\\.\\Pipe\\CheckOne" wide //weight: 1
        $x_1_3 = "FuckingShitonAllEarth#666" ascii //weight: 1
        $x_1_4 = "ysh3kskdfh2JKJFdskfhAD666" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_CryptInject_PVE_2147754884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PVE!MTB"
        threat_id = "2147754884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 0c 50 0f be 55 87 0f af 55 bc 0f be 45 87 8b 75 bc 2b f0 33 d6 03 ca 8b 15 ?? ?? ?? ?? 03 95 7c ff ff ff 88 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AI_2147755736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AI!MTB"
        threat_id = "2147755736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 65 78 65 00 40 61 6c 74 61 74 65 40 30 00 40 70 6c 75 73 54 6f 6b 65 6e 41 66 74 65 72 40 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_KC_2147756258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.KC"
        threat_id = "2147756258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Furk KeySystem" ascii //weight: 1
        $x_1_2 = "FurkOS.Properties.Resources" ascii //weight: 1
        $x_1_3 = "D:\\YT stuff\\Sources\\FurkOS\\FurkOS\\obj\\Release\\FurkOS.pdb" ascii //weight: 1
        $x_1_4 = "D:\\YT stuff\\FurkOS\\FurkOS\\obj\\Release\\FurkOS.pdb" ascii //weight: 1
        $x_1_5 = "FurkOS.Form1.resources" ascii //weight: 1
        $x_1_6 = "FurkOS.Properties.Resources.resources" ascii //weight: 1
        $x_1_7 = "FurkOS.ks.resources" ascii //weight: 1
        $x_1_8 = "furkTabs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_CryptInject_AB_2147756483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AB!MTB"
        threat_id = "2147756483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 56 a3 ?? ?? ?? ?? 0f b7 35 ?? ?? ?? ?? 81 e6 ff 7f 00 00 81 3d ?? ?? ?? ?? e7 08 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fb 85 02 00 00 75 ?? 56 56 56 56 56 ff 15 ?? ?? ?? ?? 56 56 56 56 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 2f 81 fb 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DSA_2147756795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DSA!MTB"
        threat_id = "2147756795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 8b c0 eb ?? 33 05 ?? ?? ?? ?? 8b c0 8b c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c0 8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PZ_2147757719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PZ!MTB"
        threat_id = "2147757719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 55 10 8b 45 f0 03 45 ec 0f b6 08 33 ca 8b 55 f0 03 55 ec 88 0a eb d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PZ_2147757719_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PZ!MTB"
        threat_id = "2147757719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 24 40 01 00 00 48 8d 0d ?? ?? ?? ?? 8a 04 08 88 84 24 38 01 00 00 0f b6 84 24 38 01 00 00 42 0f b6 04 00 0f b6 8c 24 30 01 00 00 33 c8 8b 84 24 40 01 00 00 88 4c 04 20 8a 84 24 30 01 00 00 fe c0 88 84 24 30 01 00 00 8b 84 24 40 01 00 00 ff c0 89 84 24 40 01 00 00 8b 84 24 40 01 00 00 41 3b c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PZ_2147757719_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PZ!MTB"
        threat_id = "2147757719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 81 7d ?? ?? ?? 00 00 73 7e 8b 4d ?? 8b 55 ?? 8b 04 8a 89 85 ?? ?? ?? ff 8b 0d ?? ?? ?? 00 89 8d ?? ?? ?? ff 8b 95 ?? ?? ?? ff 2b 55 ?? 89 95 ?? ?? ?? ff 8b 45 ?? 83 e8 50 89 45 ?? 8b 8d ?? ?? ?? ff 33 8d ?? ?? ?? ff 89 8d ?? ?? ?? ff 8b 55 ?? 81 ea ?? ?? 00 00 89 55 ?? c1 85 ?? ?? ?? ff 07 8b 85 ?? ?? ?? ff 33 85 ?? ?? ?? ff 89 85 ?? ?? ?? ff 8b 4d ?? 8b 55 ?? 8b 85 ?? ?? ?? ff 89 04 8a e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 01 89 4d ?? 81 7d ?? 84 03 00 00 73 ?? 8b 55 ?? 8b 45 ?? 8b 0c 90 89 8d ?? ?? ?? ff 8b 15 ?? ?? ?? ?? 89 95 ?? ?? ?? ff 8b 85 ?? ?? ?? ff 2b 45 ?? 89 85 ?? ?? ?? ff 8b 4d ?? 83 e9 50 89 4d ?? 8b 95 ?? ?? ?? ff 33 95 ?? ?? ?? ff 89 95 ?? ?? ?? ff 8b 45 ?? 2d e8 03 00 00 89 45 ?? c1 85 ?? ?? ?? ff 07 8b 8d ?? ?? ?? ff 33 8d ?? ?? ?? ff 89 8d ?? ?? ?? ff 8b 55 ?? 8b 45 ?? 8b 8d ?? ?? ?? ff 89 0c 90 e9 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c2 01 89 55 ?? 81 7d ?? 84 03 00 00 73 ?? 8b 45 ?? 8b 4d ?? 8b 14 81 89 55 ?? a1 ?? ?? ?? ?? 89 45 ?? 8b 4d ?? 2b 4d ?? 89 4d ?? 8b 55 ?? 83 ea 50 89 55 ?? 8b 45 ?? 33 45 ?? 89 45 ?? 8b 4d ?? 81 e9 e8 03 00 00 89 4d ?? c1 45 ?? 07 8b 55 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 8b 4d ?? 8b 55 ?? 89 14 81 eb}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c2 01 89 55 ?? 81 7d ?? 84 03 00 00 73 ?? 8b 45 ?? 8b 4d ?? 8b 14 81 89 95 ?? ?? ?? ff a1 ?? ?? ?? ?? 89 45 ?? 8b 8d ?? ?? ?? ff 2b 4d ?? 89 8d ?? ?? ?? ff 8b 55 ?? 83 ea 50 89 55 ?? 8b 85 ?? ?? ?? ff 33 45 ?? 89 85 ?? ?? ?? ff 8b 4d ?? 81 e9 e8 03 00 00 89 4d ?? c1 85 ?? ?? ?? ff 07 8b 95 ?? ?? ?? ff 33 55 ?? 89 95 ?? ?? ?? ff 8b 45 ?? 8b 4d ?? 8b 95 ?? ?? ?? ff 89 14 81 e9 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_KT_2147757767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.KT"
        threat_id = "2147757767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\documents\\visual studio 2010\\Projects\\DEltaFork\\x64\\Release\\DEltaFork.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RBA_2147757866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RBA!MTB"
        threat_id = "2147757866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 2e eb ed 8b 45 ?? 03 45 ?? 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 45 ?? 03 45 ?? 89 45 ?? 81 3d ?? ?? ?? ?? 76 09 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SN_2147757947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SN!MTB"
        threat_id = "2147757947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 30 00 00 68 ?? ?? 00 00 6a 00 e8 ?? ?? ?? ?? 89 45 fc 33 c9 bb}  //weight: 2, accuracy: Low
        $x_2_2 = {85 c9 76 33 8b c1 bf 05 00 00 00 33 d2 f7 f7 85 d2 75 ?? 8a 03 34 ?? 8b 55 fc 03 d1 73 05 e8 ?? ?? ?? ?? 88 02 eb 10 8b 45 fc 03 c1 73 05 e8 ?? ?? ?? ?? 8a 13 88 10 41 43 81 f9 ?? ?? 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SL_2147757959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SL!MTB"
        threat_id = "2147757959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "dan\\wsdl\\paypal" ascii //weight: 5
        $x_1_2 = "SwatVelamen.dll" ascii //weight: 1
        $x_5_3 = "%%\\rundll32.exe SwatVelamen,Pretor" ascii //weight: 5
        $x_1_4 = "webservices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_KS_2147758049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.KS"
        threat_id = "2147758049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "handler-execution.exe" ascii //weight: 1
        $x_1_2 = "HandlerExecution.Properties" ascii //weight: 1
        $x_1_3 = "handler-execution.g.resources" ascii //weight: 1
        $x_1_4 = "gJmuCVbFHLiKjGaGL1.tH7mVLwa4RepgWgcXe" ascii //weight: 1
        $x_1_5 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_6 = "HandlerExecution.Properties.Resources.resources" ascii //weight: 1
        $x_1_7 = "handler-execution.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RBB_2147758083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RBB!MTB"
        threat_id = "2147758083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 69 72 74 66 ?? ?? ?? ?? ?? ?? 75 61 c6 05 ?? ?? ?? ?? 6c ff 15 0d 00 c6 05 ?? ?? ?? ?? 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {7c 00 6c ff 15 35 00 c6 05 ?? ?? ?? ?? 6f c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 61 c6 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_KL_2147759461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.KL"
        threat_id = "2147759461"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\workspace\\workspace_c\\FpHGg8Jo3h46_12\\Release\\FpHGg8Jo3h46_12.pdb" ascii //weight: 1
        $x_1_2 = "gfehi7.2ihsfa" ascii //weight: 1
        $x_1_3 = "EdgeCookiesView\\Release\\EdgeCookiesView.pdb" ascii //weight: 1
        $x_1_4 = "reports.adexpertsmedia" ascii //weight: 1
        $x_1_5 = "jfiag_gg.exe" ascii //weight: 1
        $x_1_6 = "fjgha23_fa.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BN_2147759662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BN!MTB"
        threat_id = "2147759662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 44 04 08 40 3d ?? ?? 00 00 72 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 34 14 0f b6 d3 03 c2 99 b9 ?? ?? 00 00 f7 f9 45 0f b6 54 14 14 30 55 ff 83 bc 24 50 0c 00 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c4 1c ff d6 5f 5e 5d b0 01 5b 59 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_FB_2147759820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.FB!MTB"
        threat_id = "2147759820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 57 8d 14 06 e8 ?? ?? ?? ?? 30 02 46 59 3b 75 10 72 eb 5f 5e 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 33 db 33 d2 8b 45 08 8a 10 80 ca ?? 03 da d1 e3 03 45 10 8a 08 84 c9 e0 ee 33 c0 8b 4d 0c 3b d9 74}  //weight: 1, accuracy: Low
        $x_1_3 = {64 ff 35 30 00 00 00 58 8b 40 0c 8b 48 0c 8b 11 8b 41 30 6a 02 8b 7d 08 57 50 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {83 c0 04 89 45 ?? 8b 45 ?? c7 44 05 ?? 65 6c 33 32 8b 45 ?? 83 c0 04 89 45 ?? 8b 45 ?? c7 44 05 ?? 2e 64 6c 6c 8b 45 ?? 83 c0 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_FA_2147760117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.FA!MTB"
        threat_id = "2147760117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f7 29 74 24 10 89 1d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 [0-48] 8b 54 24 10 8b 74 24 ?? 89 16 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 01 c3 20 00 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 9b 00 00 00 00 81 f9 ?? ?? ?? ?? 75 ?? e8 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 7c ?? ff 15 ?? ?? ?? ?? 8b 8c 24 ?? ?? 00 00 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RBC_2147760373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RBC!MTB"
        threat_id = "2147760373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 11 00 00 c7 44 24 ?? ?? ?? ?? ?? 75 06 00 81 3d}  //weight: 1, accuracy: Low
        $x_10_2 = {89 44 24 34 75 18 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 ?? a1}  //weight: 10, accuracy: Low
        $x_10_3 = {89 44 24 34 75 13 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 89 44 24 ?? 8b}  //weight: 10, accuracy: Low
        $x_1_4 = {c3 04 00 00 75 0b 00 8b ?? c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_MLS_2147761127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MLS!MTB"
        threat_id = "2147761127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 04 89 4d ?? c7 45 ec 0f 0d 00 00 c7 45 ec 0f 0d 00 00 e8 ?? ?? ?? ?? ba 39 00 00 00 85 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_B_2147761290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.B!MTB"
        threat_id = "2147761290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d fc 03 0d ?? ?? ?? ?? 8b 55 f4 03 15 ?? ?? ?? ?? 8a 02 88 01 33 c9 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RI_2147761629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RI!MTB"
        threat_id = "2147761629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Nullsoft Install System" ascii //weight: 1
        $x_5_2 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 [0-15] 2c 58 79 6c 6f 6c 3f 00 00 2e 64 6c 6c}  //weight: 5, accuracy: Low
        $x_1_3 = "Can't initialize plug-ins directory" ascii //weight: 1
        $x_1_4 = "Corrupted installer?" ascii //weight: 1
        $x_1_5 = "Execute:" ascii //weight: 1
        $x_1_6 = "$$\\wininit.in" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_2147761693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject!ibt"
        threat_id = "2147761693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b 11 81 f2 13 6e 78 07 89 11 83 c0 04 3b f0 ?? ?? 83 ee 78 89 75 d0 8b 45 fc 89 45 d4 c7 45 d8 00 1e 00 00 c7 45 dc 4b 54 00 00 c7 45 e0 a5 53 00 00 b8 b8 c7 49 00 89 45 e8 8d 45 f8 50 6a 40 8b 45 f4 50 8b 45 fc 50 ?? ?? ?? ?? ?? 81 45 fc 30 54 00 00 8b 45 fc 8d 55 d0 52 ff d0}  //weight: 1, accuracy: Low
        $x_1_2 = "mstsc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_ART_2147763119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.ART!MTB"
        threat_id = "2147763119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PHs PHs2PHsFPHsXPHslPHs~PHs" ascii //weight: 1
        $x_1_2 = "Gs8LHszJHs.BHs>BHs[BHsmBHs" ascii //weight: 1
        $x_1_3 = "QHs*QHs<QHsPQHsbQHsvQHs" ascii //weight: 1
        $x_1_4 = "RHs RHs4RHsFRHsZRHslRHs" ascii //weight: 1
        $x_1_5 = "tavernHotelDirectorySystem.Mail46UC" ascii //weight: 1
        $x_1_6 = "VHs\"VHs6VHsHVHs\\VHsnVHs" ascii //weight: 1
        $x_1_7 = {66 0f b6 04 11 [0-79] 2b 42 14 89 85 [0-4] 8b 0d [0-79] 66 81 c2 00 01 [0-79] 8b 85 [0-4] 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_CryptInject_DSB_2147763774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DSB!MTB"
        threat_id = "2147763774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 2b c6 8b 4d ?? 89 01 8b 55 ?? 8b 02 05 5c 11 00 00 8b 4d ?? 89 01 8b 55 ?? 8b 02 2d 5c 11 00 00 8b 4d ?? 89 01 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d2 8b d2 a1 ?? ?? ?? ?? 8b d2 8b 0d ?? ?? ?? ?? 8b d2 a3 ?? ?? ?? ?? 8b c0 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 33 d9 c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PO_2147766836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PO!MTB"
        threat_id = "2147766836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 c1 ea ?? 8d 04 52 8d 04 41 8b ce 03 c3 8d 04 40 2b c8 8a 44 0c ?? 30 04 37 46 8b 4c 24 ?? 81 fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BQ_2147767519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BQ!MTB"
        threat_id = "2147767519"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "@SetViceCitiesz@0" ascii //weight: 1
        $x_1_2 = {8b ff 8b c6 e8 ?? ?? ff ff 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 0b 6a 00 8d 85 ?? ?? ff ff 50 ff d7 46 3b 35 ?? ?? ?? 00 72 d9}  //weight: 1, accuracy: Low
        $x_1_3 = {88 14 01 c3 1f 00 8b 0d ?? ?? ?? ?? 8a 94 01 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 14 01 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BU_2147769159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BU!MTB"
        threat_id = "2147769159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {ac 32 02 aa 42 49 83 ec 04 c7 04 24 93 dc 00 05 83 c4 04 85 c9 75}  //weight: 5, accuracy: High
        $x_5_2 = {ac 83 ec 04 c7 04 24 5e d0 7d db 83 c4 04 32 02 aa 42 49 85 c9 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_BU_2147769159_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BU!MTB"
        threat_id = "2147769159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d f8 03 de 8a 01 88 45 f5 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f5 32 45 f6 88 03 8a 03 32 45 f7 88 03 eb 05 8a 45 f5 88 03 46 41 4f 75 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BX_2147770209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BX!MTB"
        threat_id = "2147770209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 fc 03 f7 8a 03 88 45 fa 57 58 51 6a 03 59 60 61 33 d2 f7 f1 59 09 d2 75 11 8a 45 fa 32 45 f9 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 fa 88 06 47 43 49 75 ca 8b 7d ec 8b 75 f0 8b 5d f4 55 5c 5d c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BV_2147771162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BV!MTB"
        threat_id = "2147771162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 45 d8 29 45 e8 e9 ?? ff ff ff 8b 4d 08 8b 55 d0 89 11 8b 45 08 8b 4d f4 89 48 04 8b e5 5d c2 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5d 08 8d 5c 9d e0 8b 33 8b ce 23 cf 89 4d f0 8b ca d3 ee 8b 4d fc 0b 75 f4 89 33 8b 75 f0 d3 e6 ff 45 08 83 7d 08 03 89 75 f4 7c d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PK_2147772982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PK!MTB"
        threat_id = "2147772982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "prgDownload" wide //weight: 1
        $x_1_2 = "http://photos-a.ak.fbcdn.net/hphotos-ak-ash4/299285_2248555626619_1630054477_2231616_929070348_a.jpg" wide //weight: 1
        $x_1_3 = {5c 49 6e 6f 66 65 6e 73 69 76 6f 5c 65 78 70 61 6e 73 69 6f 6e 5c [0-32] 5c 44 65 62 75 67 5c 77 6d 76 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_ZA_2147773592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.ZA!MTB"
        threat_id = "2147773592"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 05 00 00 00 2b 88 ?? ?? ?? ?? 01 88 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 48 ?? 81 f1 ?? ?? ?? ?? 0f af 4a ?? 89 4a ?? 8b 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 88 ?? ?? ?? ?? 31 88 b0 00 00 00 8b ce 0f af ce 46 01 88 ?? ?? ?? ?? 3b 70 ?? 76 b0}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 ea 18 01 86 ?? ?? ?? ?? 8b 4e ?? 8b 86 ?? ?? ?? ?? 88 14 01 8b cb ff 46 ?? a1 ?? ?? ?? ?? 8b 56 ?? c1 e9 10 8b 80 ?? ?? ?? ?? 88 0c 02 8b d3 ff 46 ?? a1 ?? ?? ?? ?? c1 ea}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_ZB_2147773593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.ZB!MTB"
        threat_id = "2147773593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 d2 8b c6 f7 f1 8b 45 ?? 8a 0c 02 8d 14 3e 8b 45 ?? 46 8a 04 10 32 c1 88 02 3b f3 72}  //weight: 1, accuracy: Low
        $x_1_2 = "doc-scan.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SF_2147776867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SF!MTB"
        threat_id = "2147776867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "F:\\01_FG\\02_selfproject\\01_runtask\\01_miansha\\MyJiake2-dest\\Release\\MyJiake.pdb" ascii //weight: 1
        $x_1_2 = "C:\\INTERNAL\\REMOTE.EXE" wide //weight: 1
        $x_1_3 = "Shadow Defender\\Service.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AMK_2147787590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AMK!MTB"
        threat_id = "2147787590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b c1 8b 4d f8 0f b6 4c 0d ?? 8b 55 f8 2b 55 ?? 0f b6 54 15 ?? 0f b7 54 55 ?? 23 ca 2b c1 8b 4d f8 0f b6 4c 0d ?? 66 89 44 4d}  //weight: 10, accuracy: Low
        $x_10_2 = {33 c0 40 c1 e0 00 0f b6 44 05 ?? 83 c8 ?? 33 c9 41 c1 e1 00 0f b6 4c 0d ?? 83 e1 ?? 2b c1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_D_2147789155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.D!MTB"
        threat_id = "2147789155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gift.zip" ascii //weight: 1
        $x_1_2 = "VCDDaemon.exe" ascii //weight: 1
        $x_1_3 = "KaikiUpdate" ascii //weight: 1
        $x_1_4 = "L2dpZnQyLnppcA" ascii //weight: 1
        $x_1_5 = "L2dpZnQuemlw" ascii //weight: 1
        $x_1_6 = "ISMyMDIxQ3liZXJINGNLM3JAJQ" ascii //weight: 1
        $x_1_7 = "ZXhlY3VjYW8ucGhw" ascii //weight: 1
        $x_1_8 = "d3d3LnJlc3RhdXJhbnRlY2hhbmdheS5jb20uYnI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PU_2147793604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PU!MTB"
        threat_id = "2147793604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 15 05 00 00 74 ?? 83 3d ?? ?? ?? ?? 00 8b 55 0c 8b 4d f8 8b 04 8a 8b 55 14 8b 4d fc 33 04 8a 8b 55 08 8b 4d f8 89 04 8a 83 3d ?? ?? ?? ?? 00 74 ?? 83 3d ?? ?? ?? ?? 00 74 ?? c7 05 ?? ?? ?? ?? 93 0c 00 00 83 3d ?? ?? ?? ?? 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_FJEM_2147793682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.FJEM!MTB"
        threat_id = "2147793682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chaetopodous7" wide //weight: 1
        $x_1_2 = "anvendelsesmuligheder" wide //weight: 1
        $x_1_3 = "Haandgemngets" wide //weight: 1
        $x_1_4 = "Mishanter2" wide //weight: 1
        $x_1_5 = "Microspectrophotometres" wide //weight: 1
        $x_1_6 = "Jordpaakastelserne8" wide //weight: 1
        $x_1_7 = "Pietister9" wide //weight: 1
        $x_1_8 = "Anstandsdamerne" wide //weight: 1
        $x_1_9 = "ClashCannon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_FJC_2147793991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.FJC!MTB"
        threat_id = "2147793991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fstningsvrkernes6" ascii //weight: 1
        $x_1_2 = "Tilkrselsrampen5" ascii //weight: 1
        $x_1_3 = "Vindmlleprojektet1" ascii //weight: 1
        $x_1_4 = "Kunstudstillinger6" ascii //weight: 1
        $x_1_5 = "ventroposterior" ascii //weight: 1
        $x_1_6 = "sekretionen" ascii //weight: 1
        $x_1_7 = "bobinets" ascii //weight: 1
        $x_1_8 = "SKAANEPROGRAMMETS" ascii //weight: 1
        $x_1_9 = "INTERGULAR" ascii //weight: 1
        $x_1_10 = "sammenligningsoperatorernes" ascii //weight: 1
        $x_1_11 = "emissionsgrnsevrdier" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_FDSD_2147795823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.FDSD!MTB"
        threat_id = "2147795823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 85 53 fa ?? ?? ac c6 85 54 fa ?? ?? 24 c6 85 55 fa ?? ?? 64 c6 85 56 fa ?? ?? fc c6 85 57 fa ?? ?? ?? c6 85 58 fa ?? ?? ?? c6 85 59 fa ?? ?? 81 c6 85 5a fa ?? ?? ec c6 85 5b fa ?? ?? 1c c6 85 5c fa ?? ?? 04 c6 85 5d fa ?? ?? 00 c6 85 5e fa ?? ?? 00 c6 85 5f fa ?? ?? 8b c6 85 60 fa ?? ?? 8d c6 85 61 fa ?? ?? a4}  //weight: 1, accuracy: Low
        $x_1_2 = {3e c7 43 30 69 00 00 00 eb f6 74 f4 83 c0 78 c1 e0 05 09 d1 85 f3 74 24 83 e3 10 8d 53 c0 c1 eb 69 c1 ee 58 7c da}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 98 83 e8 20 83 e0 11 33 85 fc f9 ?? ?? 66 89 85 14 fa ?? ?? 8b 4d dc 83 c1 09 33 8d 68 ff ff ff 0b 4d c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_FDSE_2147796178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.FDSE!MTB"
        threat_id = "2147796178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2c 30 82 54 d9 d9 6d ed f2 32 30 12 28 2c ae 24 16}  //weight: 1, accuracy: High
        $x_1_2 = {33 10 8b 5d ec b1 9f ee 20 7f 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptInject_INJT_2147797367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.INJT!MTB"
        threat_id = "2147797367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {84 5c d0 1f 10 20 48 26 e4 42 30 22 14 4b 2e 64 40}  //weight: 5, accuracy: High
        $x_5_2 = {30 74 ec 8e 30 73 7f 2a 70 08}  //weight: 5, accuracy: High
        $x_10_3 = {24 66 45 7c 43 d4 58 2b 86 48 40 6c ac c4 86 f4 d7 89 67 29 48 2f 1c fb 60 c1 7c 88 58 1b af 09 cb 74 f1 67 75 4b bf 18 94 ec d9 17 14 cf fc 41 6c 95 a2 47 df 98 92 0f 39 a2 ac 15 3f 3c 34 05}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_APR_2147799517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.APR!MTB"
        threat_id = "2147799517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 a3 e1 11 6a 01 ff 15 ?? 00 01 10}  //weight: 1, accuracy: Low
        $x_1_2 = {01 10 0f b6 05 ?? ?? 01 10 c1 f8 06 0f b6 0d ?? ?? 01 10 c1 e1 02 0b c1 a2 ?? ?? 01 10 0f b6 ?? ?? ?? 01 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CM_2147807405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CM!MTB"
        threat_id = "2147807405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\work\\productSvc\\OutPutFile\\Release\\SevenDayBJSvc.pdb" ascii //weight: 1
        $x_1_2 = "SevenDayBJ.exe" ascii //weight: 1
        $x_1_3 = "SevenDayBJ Service" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "OutputDebugStringW" ascii //weight: 1
        $x_1_6 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_7 = "GetTickCount64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CN_2147807563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CN!MTB"
        threat_id = "2147807563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 06 33 c1 c1 e9 08 0f b6 c0 33 0c 85 10 14 43 00 46 83 ea 01 75 e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 06 33 c3 83 e0 01 31 06 8b 3d 2c 4a 43 00 42 81 c6 18 08 00 00 3b d7 72 cb}  //weight: 1, accuracy: High
        $x_1_3 = {8a 04 0e 88 01 41 83 ea 01 75 f5}  //weight: 1, accuracy: High
        $x_1_4 = "2345SafeTray.exe" ascii //weight: 1
        $x_1_5 = "C:\\TEMP\\bf.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CE_2147808323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CE!MTB"
        threat_id = "2147808323"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FBIMAGE.DLL" ascii //weight: 1
        $x_1_2 = "c:\\windows\\temp" ascii //weight: 1
        $x_1_3 = "chings@163.net" ascii //weight: 1
        $x_1_4 = "Firebird Workroom" ascii //weight: 1
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CH_2147808435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CH!MTB"
        threat_id = "2147808435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 f6 74 01 ea 31 31 81 c1 04 00 00 00 39 c1 75 ef}  //weight: 1, accuracy: High
        $x_1_2 = {81 c3 65 6e 08 a9 42 bf 3d 20 28 14 81 fa 42 4c 00 01 75 af}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AC_2147811074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AC!MTB"
        threat_id = "2147811074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 cb 59 f7 db f7 d3 81 c3 [0-4] 29 d8 5b ff 20}  //weight: 1, accuracy: Low
        $x_1_2 = {89 e9 81 c1 [0-4] 2b 31 89 e9 81 c1 [0-4] 31 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_GDT_2147812775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.GDT!MTB"
        threat_id = "2147812775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ca 8b f2 83 e1 1f 33 f0 d3 ce 3b f7 74 69 85 f6 74 04}  //weight: 10, accuracy: High
        $x_10_2 = {8b c1 83 e1 3f c1 f8 06 6b c9 30 8b 04 85 ?? ?? ?? ?? f6 44 08 28 01 74 06}  //weight: 10, accuracy: Low
        $x_1_3 = "ontdll.dll" ascii //weight: 1
        $x_1_4 = "equickseeinst.exe" ascii //weight: 1
        $x_1_5 = "quickseeinst.dll" ascii //weight: 1
        $x_1_6 = "URLDownloadToFile" ascii //weight: 1
        $x_1_7 = "LoadResource" ascii //weight: 1
        $x_1_8 = "ShellExecute" ascii //weight: 1
        $x_1_9 = "CryptEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CI_2147812939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CI!MTB"
        threat_id = "2147812939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 ff 74 01 ea 31 07 42 81 c7 04 00 00 00 39 df 75 ee}  //weight: 1, accuracy: High
        $x_1_2 = {81 c1 01 00 00 00 81 eb 2b da 8f 9b 89 db 81 f9 7d db 00 01 75 a3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CP_2147814550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CP!MTB"
        threat_id = "2147814550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 9e 06 00 00 74 12 40 3d f6 74 13 01 89 44 24 1c 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 14 40 3d c7 de 80 00 89 44 24 14 0f 8c}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CT_2147815299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CT!MTB"
        threat_id = "2147815299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 8a 00 88 45 eb 0f be 45 eb 89 45 f4 8b 45 ec 31 45 f4 8b 45 f4 88 45 eb 8a 55 eb 8b 45 e0 88 10 ff 45 e0 ff 45 dc ff 45 f0 8b 45 f0 3b 45 0c 0f 9c c0 84 c0 75 c7}  //weight: 1, accuracy: High
        $x_1_2 = "Scanning for VMware" ascii //weight: 1
        $x_1_3 = "Scanning for Sandboxie" ascii //weight: 1
        $x_1_4 = "VMware detected!" ascii //weight: 1
        $x_1_5 = "Sandboxie detected!" ascii //weight: 1
        $x_1_6 = "Decrypting" ascii //weight: 1
        $x_1_7 = "Unpacking Successful" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CX_2147815324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CX!MTB"
        threat_id = "2147815324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 04 16 30 04 13 83 c2 01 39 d5 77 f2}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 4c 03 01 30 4c 14 20 8d 50 02 39 d7 76 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MG_2147815839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MG!MTB"
        threat_id = "2147815839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 7c ff ff ff 04 00 00 00 8d 55 fc 52 68 95 0c 00 00 68 ?? ?? ?? ?? ff 75 f8 ff 75 e8 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 1e c1 e3 04 03 5f 08 8b 06 01 d0 31 c3 8b 06 c1 e8 05 03 47 0c 31 c3 29 5e 04 8b 5e 04 c1 e3 04 03 1f 8b 46 04 01 d0 31 c3 8b 46 04 c1 e8 05 03 47 04 31 c3 29 1e 81 c2 ?? ?? ?? ?? 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DF_2147816412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DF!MTB"
        threat_id = "2147816412"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 c1 8a 0f 03 4d f4 81 e1 ff 00 00 00 8a 0c 19 30 08}  //weight: 2, accuracy: High
        $x_2_2 = {8a 14 18 03 c3 88 17 89 4d f4 88 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DG_2147816478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DG!MTB"
        threat_id = "2147816478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 14 0c 32 14 29 83 c0 01 80 f2 8d 88 11 83 c1 01 83 ef 01 75 da}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DD_2147816560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DD!MTB"
        threat_id = "2147816560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 ee 33 c5 33 44 24 10 68 b9 79 37 9e 8d 54 24 20 52 2b f8}  //weight: 1, accuracy: High
        $x_1_2 = {81 ff ee 75 37 00 7f 09 47 81 ff f6 ea 2b 33 7c 87}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DE_2147816817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DE!MTB"
        threat_id = "2147816817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 8b f8 32 40 00 8a c1 0a cc 22 c4 f6 d0 22 c1 43 8a e0 88 24 3e 83 fb 04 72 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DE_2147816817_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DE!MTB"
        threat_id = "2147816817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c8 33 4d fc 89 4d fc 8b 55 08 83 c2 01 89 55 08 c7 45 f8 00 00 00 00 eb 09}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DJ_2147816913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DJ!MTB"
        threat_id = "2147816913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b f7 33 f1 81 e6 [0-4] 33 f1 8b 4a 08 89 71 04 8b 52 0c 85 d2 75 a2}  //weight: 2, accuracy: Low
        $x_1_2 = "msocxusys.dll" ascii //weight: 1
        $x_1_3 = "snxapi.exe" ascii //weight: 1
        $x_1_4 = "Encrypt" ascii //weight: 1
        $x_1_5 = "sgvrfy32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DI_2147816927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DI!MTB"
        threat_id = "2147816927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 90 32 c2 88 07 42 90 46 90 e9}  //weight: 2, accuracy: High
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DK_2147817067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DK!MTB"
        threat_id = "2147817067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 f3 f4 c9 c6 27 81 84 24 [0-8] 35 16 4f e3 0c c1 e0 1f}  //weight: 2, accuracy: Low
        $x_2_2 = {46 81 fe bd ef 09 37 0f 8c [0-4] 33 c9 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DL_2147817453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DL!MTB"
        threat_id = "2147817453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {3d 8d cc 05 00 75 06 81 c1 fa 23 0a 00 40 3d 0f 7e 49 00 7c eb}  //weight: 2, accuracy: High
        $x_2_2 = {3d 50 4f 02 00 75 06 89 0d [0-4] 40 3d 6c 17 30 32 7c eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DO_2147817469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DO!MTB"
        threat_id = "2147817469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 45 b8 bd 15 07 42 81 6d 98 e6 13 c0 4a 81 45 d8 9c c4 21 1f 81 45 a0 43 58 2a 1c 8b 45 fc 33 c2 33 c1 81 3d [0-4] a3 01 00 00 89 45 fc 75 20}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 60 4b da 26 7f 0c 40 3d b6 ad 81 5b 0f 8c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DP_2147817595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DP!MTB"
        threat_id = "2147817595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 8c 30 31 a2 00 00 8b 15 [0-4] 88 0c 32 83 3d [0-4] 33 75 12}  //weight: 5, accuracy: Low
        $x_2_2 = {81 fe ce 0d 26 09 0f 8f [0-4] 46 81 fe 9c b3 61 36 7c af}  //weight: 2, accuracy: Low
        $x_2_3 = {53 53 53 ff d7 46 81 fe 74 6c 5f 00 7c d5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DQ_2147817667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DQ!MTB"
        threat_id = "2147817667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 4e 8b 06 8b d0 4f 46 8b 07 33 c2 47 46 8a c4 ff 0c 24 aa 58 8b d0 85 c0 75 08}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 ff 75 08 6a 00 6a 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 00 00 cf 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DC_2147817825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DC!MTB"
        threat_id = "2147817825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d 08 8a 11 02 55 f8 8b 45 08 88 10 8b 4d 08 8a 11 32 55 f8 8b 45 08 88 10 8b 4d 08 83 c1 01 89 4d 08 eb 9e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DS_2147818358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DS!MTB"
        threat_id = "2147818358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 45 fc 8b 45 fc 8a 04 38 8b 0d [0-4] 88 04 0f 83 3d [0-4] 44 75 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {81 ff 0e 77 00 00 75 05 e8 [0-4] 47 81 ff 7d b9 86 02 7c e3}  //weight: 2, accuracy: Low
        $x_1_3 = "fiwezejicetizucovedakewa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DT_2147819177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DT!MTB"
        threat_id = "2147819177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tryytAFrstdtyf^WTUw" ascii //weight: 2
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DU_2147819313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DU!MTB"
        threat_id = "2147819313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d8 83 e0 1f 8a 80 [0-4] 30 04 1e c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 [0-4] 83 ec 10 e8 [0-4] 30 04 1e}  //weight: 2, accuracy: Low
        $x_2_2 = "Dsl32.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DV_2147819396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DV!MTB"
        threat_id = "2147819396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d8 83 e0 1f 8a 80 24 50 40 00 30 04 1e c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 [0-4] 83 ec 10 e8 [0-4] 30 04 1e c7 44 24 0c 00 00 00 00 c7 44 24 08 00 00 00 00 c7 44 24 04 00 00 00 00 c7 04 24 00 00 00 00 e8 [0-4] 83 ec 10 43 39 fb 75 97}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DW_2147819560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DW!MTB"
        threat_id = "2147819560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 04 [0-4] 8b 94 24 [0-4] 01 c2 31 ca 88 94 04 [0-4] 83 c0 01 83 f8 2d 75 de}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AG_2147822365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AG!MSR"
        threat_id = "2147822365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "StartW" ascii //weight: 1
        $x_1_2 = "UpdateW" ascii //weight: 1
        $x_1_3 = "images/theme/log.php" ascii //weight: 1
        $x_1_4 = "103.213.247.48" ascii //weight: 1
        $x_1_5 = "Download.dll" ascii //weight: 1
        $x_1_6 = "WinHttpConnect" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DX_2147823177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DX!MTB"
        threat_id = "2147823177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fEXcXV.dll" ascii //weight: 1
        $x_1_2 = "ywuMLjBv.dll" ascii //weight: 1
        $x_1_3 = "BIitdAdBkB.dll" ascii //weight: 1
        $x_1_4 = "mXxRIqNQzj.dll" ascii //weight: 1
        $x_1_5 = "mUEkdPJY.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DY_2147824753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DY!MTB"
        threat_id = "2147824753"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 0a 34 44 04 19 88 01 41 4e 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DZ_2147825080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DZ!MTB"
        threat_id = "2147825080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 00 33 d0 33 8c 95 [0-4] 89 4d fc 8b 4d ec 83 c1 01 89 4d ec eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CY_2147828793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CY!MTB"
        threat_id = "2147828793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NtTerminate.exe" ascii //weight: 1
        $x_1_2 = "I.LOVE.YOU.txt.vbs" ascii //weight: 1
        $x_1_3 = "vmware" ascii //weight: 1
        $x_1_4 = "[i Love You]" ascii //weight: 1
        $x_1_5 = "sandbox" ascii //weight: 1
        $x_1_6 = "arrayService.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BT_2147830987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BT!MTB"
        threat_id = "2147830987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AE07A16A-8FB6-43fc-BB91-2D945E2148ED" wide //weight: 2
        $x_2_2 = "Global\\{66D5E4CB-9FFD-4380-B6F7-B4F814C61DC6}" wide //weight: 2
        $x_2_3 = "s\\%04x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x.res" wide //weight: 2
        $x_1_4 = "ServiceMain" ascii //weight: 1
        $x_1_5 = "DllRegister" ascii //weight: 1
        $x_1_6 = "ServiceHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PN_2147836877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PN!MTB"
        threat_id = "2147836877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libwinpthread-1.dll" ascii //weight: 1
        $x_1_2 = "powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_SPQ_2147837219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.SPQ!MTB"
        threat_id = "2147837219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 18 32 d9 80 f3 80 88 18 40 38 10 75 f2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CG_2147838783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CG!MTB"
        threat_id = "2147838783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 10 73 ?? 8b 4d fc 03 4d f4 8b 55 f8 03 55 f4 8a 02 88 01 eb}  //weight: 8, accuracy: Low
        $x_6_2 = "red lips" ascii //weight: 6
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_NEAA_2147841212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.NEAA!MTB"
        threat_id = "2147841212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "NFTQo270U Supsup Setup" wide //weight: 5
        $x_5_2 = "SetupLdr.exe" ascii //weight: 5
        $x_1_3 = "macukraine" ascii //weight: 1
        $x_1_4 = "csiso2022jp" ascii //weight: 1
        $x_1_5 = "macromania" ascii //weight: 1
        $x_1_6 = "26.0.36039.7899" ascii //weight: 1
        $x_1_7 = "kWinapi.PsAPI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_LP_2147845743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.LP!MTB"
        threat_id = "2147845743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 fc 00 00 00 00 64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 40 10 89 45 fc 8b 45 fc 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_2147846860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MTO!MTB"
        threat_id = "2147846860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTO: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe c2 02 9c 15 16 10 00 00 8a 84 15 16 10 00 00 8a ac 1d 16 10 00 00 88 84 1d 16 10 00 00 88 ac 15 16 10 00 00 02 c5 47 8a 84 05 16 10 00 00 30 07 fe c9 4e 75 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YHA_2147846954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YHA!MTB"
        threat_id = "2147846954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 8b 75 cc 31 ce 0f b6 4d ?? 8b 7d f0 0f b6 5c 0f 03 31 f3 88 d8 88 44 0f 03 0f b6 45 ef 83 c0 04 88 c1 88 4d ef e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MQ_2147847378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MQ!MTB"
        threat_id = "2147847378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 76 00 61 00 6e 00 64 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 [0-8] 70 00 6f 00 73 00 6c 00 65 00 64 00 [0-4] 5c 00 41 00 50 00 43 00 52 00 43 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "AVT1picture.id" wide //weight: 1
        $x_1_3 = "eliforPresU" wide //weight: 1
        $x_1_4 = "ataDppA" wide //weight: 1
        $x_1_5 = "Programmer - James Dougherty" wide //weight: 1
        $x_1_6 = "Ariel Productions" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PAAN_2147848842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PAAN!MTB"
        threat_id = "2147848842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://www.wjmshome.com/SecretChat.htm" ascii //weight: 1
        $x_1_2 = "\\jiami.exe" ascii //weight: 1
        $x_1_3 = "WinSta0\\Default" ascii //weight: 1
        $x_1_4 = "Applications\\iexplore.exe\\shell\\open\\command" ascii //weight: 1
        $x_1_5 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BKC_2147852640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BKC!MTB"
        threat_id = "2147852640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b 44 24 08 5d 01 c5 32 5d 00 81 e3 ff 00 00 00 8b 14 24 8b 2a c1 e3 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MBHW_2147853234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MBHW!MTB"
        threat_id = "2147853234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 35 00 00 0e 36 00 00 22 36 00 00 34 36 00 00 46 36}  //weight: 1, accuracy: High
        $x_1_2 = {1c 18 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 f4 14 40 00 74 14 40 00 9c 13 40 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAE_2147894666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAE!MTB"
        threat_id = "2147894666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5b 21 c1 e8 ?? ?? ?? ?? b9 3c 29 e5 1c 31 1f 81 c0 0b 6f f6 5a 81 c7 02 00 00 00 29 c0 b9 27 53 e5 1d 39 d7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MA_2147894971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MA!MTB"
        threat_id = "2147894971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 03 4d fc 0f b6 09 8b 45 fc 99 be ?? ?? ?? ?? f7 fe 8b 45 ec 0f b6 14 10 33 ca 8b 45 f8 03 45 fc 88 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MBEP_2147895729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MBEP!MTB"
        threat_id = "2147895729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 53 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 04 31 53 00 04 31 53 00 dc 13 40 00 78 00 00 00 81 00 00 00 8c 00 00 00 8d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4c 65 61 6e 69 6e 67 73 00 44 72 61 66 74 69 6e 65 73 73 00 00 54 65 72 72 61 72 69 69 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MY_2147896935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MY!MTB"
        threat_id = "2147896935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 57 31 ef 47 56}  //weight: 1, accuracy: High
        $x_1_2 = "powrprof.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PACC_2147897746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PACC!MTB"
        threat_id = "2147897746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellCodeInjection.pdb" ascii //weight: 1
        $x_1_2 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\"" wide //weight: 1
        $x_1_3 = "/hookingresults" ascii //weight: 1
        $x_1_4 = "Got VirtualAllocEx" ascii //weight: 1
        $x_1_5 = "Got WriteProcessMemory" ascii //weight: 1
        $x_1_6 = "Got CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PACG_2147897877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PACG!MTB"
        threat_id = "2147897877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /f /im taskmgr.exe" ascii //weight: 1
        $x_1_2 = "REG ADD hkcu\\Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system /v DisableTaskMgr /t reg_dword /d 1 /f" ascii //weight: 1
        $x_1_3 = "[+] CHANGING WALLPAPER" ascii //weight: 1
        $x_1_4 = "maldev.pdb" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\AssignedAccessConfiguration" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_LA_2147898346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.LA!MTB"
        threat_id = "2147898346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dHJdvghcgyhushgjdshgj" ascii //weight: 1
        $x_1_2 = {64 8b 3d 30 00 00 00 8b 7f 0c 8b 77 0c 8b 06 8b 00 8b 40 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAK_2147899044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAK!MTB"
        threat_id = "2147899044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 10 27 00 00 7d 0b 8d 8d ?? ?? ?? ?? 51 6a 00 ff d7 46 81 fe cc 9c f4 1f 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAM_2147899117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAM!MTB"
        threat_id = "2147899117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 0b c0 c8 03 32 87 ?? ?? ?? ?? 88 04 0b 8d 47 01 bf 0d 00 00 00 99 f7 ff 41 8b fa 3b ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MZF_2147900091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MZF!MTB"
        threat_id = "2147900091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 24 8b 6c 24 28 c7 44 24 2c ?? ?? ?? ?? 8b 44 24 2c 83 c4 0c 8a 0c 17 30 0c 06 47 40 3b fd 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f9 8b 4d e0 c1 e9 10 c1 e8 08 0f b6 c9 33 1c 8d ?? ?? ?? ?? 0f b6 c0 33 1c 85 ?? ?? ?? ?? 0f b6 c2 33 1c 85 ?? ?? ?? ?? 8b 45 10 33 5e 2c 8b 55 f0 89 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PACW_2147900288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PACW!MTB"
        threat_id = "2147900288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 81 c2 a5 03 ea c5 31 33 ba a8 04 2c b0 21 c2 4a 81 c3 01 00 00 00 89 c2 09 d2 81 c0 40 26 ff b3 39 fb 75 cf}  //weight: 1, accuracy: High
        $x_1_2 = {8d 34 31 52 8b 04 24 83 c4 04 b8 45 8a 5c 25 09 c2 8b 36 42 21 d0 81 e6 ff 00 00 00 52 5a 81 c1 01 00 00 00 29 d2 81 f9 f4 01 00 00 75 05 b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PACX_2147900475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PACX!MTB"
        threat_id = "2147900475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 2f 4e f6 c5 0e 0f b3 ea 0f ac ea 52 0f ce 86 d6 0f b3 ce 0f c0 f2 8a f4 b6 26 f9 0f ad ea 0f ca 84 c1 8a d0 0f c0 d6 b2 82 f6 c5 06 f6 da eb c6}  //weight: 1, accuracy: High
        $x_1_2 = {74 40 8a d0 0f ba f2 4a 0f af d5 0f ad ea 0f af d5 b6 26 84 c1 c0 ca ea 2a f4 80 ee ee fe ca 86 f2 0f bd d5 0f bd d5 0f bd d5 b2 82 0f be f4 d2 ee 84 e5 c0 ee 36 f6 da 0a d0 8a d0 f6 da 2a f4 eb b5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_HN_2147900707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.HN!MTB"
        threat_id = "2147900707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a 0f 82 06 ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 66 81 f1 ?? ?? b9 ?? ?? ?? ?? b8 ?? ?? ?? ?? 05 ?? ?? ?? ?? bb ?? ?? ?? ?? ba ?? ?? ?? ?? 81 ea ?? ?? ?? ?? ed 81 fb ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BKR_2147901202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BKR!MTB"
        threat_id = "2147901202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 50 0c 8b 42 14 83 c2 14 3b c2 74 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAO_2147901341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAO!MTB"
        threat_id = "2147901341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b df 69 ff 63 fa 00 00 8b ca 83 e1 07 d3 eb 81 f7 71 20 85 94 30 1c 02 42 3b d6 72 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_EC_2147902192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.EC!MTB"
        threat_id = "2147902192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e0 01 85 c0 74 ?? 8a 45 ?? 30 45 ?? 8a 45 ?? 83 e0 ?? 88 45 ?? d0 65 ?? 80 7d ?? ?? 74 ?? 80 75 ?? ?? d0 6d ?? ff 45 ?? 83 7d ?? ?? 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_HB_2147902451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.HB!MTB"
        threat_id = "2147902451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 63 c2 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 89 c1 c1 f9 03 89 d0 c1 f8 1f 29 c1 89 c8 c1 e0 05 01 c8 89 d1 29 c1 48 8b 55 b8 8b 45 f8 48 98 48 01 d0 89 ca 88 10 83 45 f8 01 8b 45 f8 48 98 48 3b 45 d8 72}  //weight: 10, accuracy: Low
        $x_1_2 = "FEK.DLL" wide //weight: 1
        $x_1_3 = "CryptGenRandom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_TR_2147903863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.TR!MTB"
        threat_id = "2147903863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\WINDESTROYER.EXE" ascii //weight: 1
        $x_1_2 = "This trojan is not a joke, continue?" ascii //weight: 1
        $x_1_3 = "YOUR SYSTEM HAS BEEN DESTROYED BY WINDESTROYER.EXE" ascii //weight: 1
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
        $x_1_5 = "DisableRegistryTools" ascii //weight: 1
        $x_1_6 = "DisableCMD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_CryptInject_YAR_2147904172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAR!MTB"
        threat_id = "2147904172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c3 02 c3 32 c3 0f 1f 00 02 c3 8a ff 32 c3 8a c0 c0 c8 9b 90 aa 0f 1f 12 0f 1f 12 49 0f 1f 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_VH_2147904389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.VH!MTB"
        threat_id = "2147904389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 f7 75 ?? 8a 44 15 ?? 32 84 31 ?? ?? ?? ?? 88 04 1e 46 81 fe ?? ?? ?? ?? 72 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_NA_2147905068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.NA!MTB"
        threat_id = "2147905068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EXECUTE" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALLADDRESS" ascii //weight: 1
        $x_5_4 = "QU6A5SeaxcLUL9LFtaj70r8GN8xP3RxbBD8VfSNl" ascii //weight: 5
        $x_5_5 = "FUNC ITY60LHMXZJ4V" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHA_2147905186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHA!MTB"
        threat_id = "2147905186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {67 3d 3d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 7d 00 e8 ?? ?? 00 00 e9 ff ?? ff ff 02}  //weight: 2, accuracy: Low
        $x_2_2 = {66 8b c0 0f 31 52 8f 45 f0 50 8d 00 8f 45 14 bf 47 6b 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f 31 8d 24 24 50 66 8b ff 8f 45 f4 8b 4d 14 8b 45 f4 3b c8 0f 84 69 ff ff ff 8b d0 33 d1 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DAA_2147905637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DAA!MTB"
        threat_id = "2147905637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 0c b1 0b 33 c0 30 0c 30 40 80 c1 02 3d 04 78 00 00 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAS_2147906110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAS!MTB"
        threat_id = "2147906110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f2 45 8b 85 80 fe ff ff 88 90 ?? ?? ?? ?? 8b 8d 80 fe ff ff 83 c1 01 89 8d 80 fe ff ff 8b 95}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f1 89 00 00 00 8b 95 80 fe ff ff 88 8a ?? ?? ?? ?? 8b 85 80 fe ff ff 83 c0 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MAC_2147906381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MAC!MTB"
        threat_id = "2147906381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb c1 e1 04 03 4d ?? 8d 45 ec bf ?? ?? ?? ?? be 04 00 00 00 8a 11 30 10 41 40 4e 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 8b f2 8a 54 05 ?? 30 14 0f 41 40 89 4d ?? 3b 4d 08 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_COL_2147907166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.COL!MTB"
        threat_id = "2147907166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 c7 45 fc 1b ?? ?? ?? 8b c6 8d 0c 1e f7 75 fc 2b 55 f8 8a 44 15 cc 32 04 39 46 88 01 81 fe 00 62 07 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHB_2147908005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHB!MTB"
        threat_id = "2147908005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dhX2PxzHzqnt.tip" ascii //weight: 1
        $x_1_2 = "?HidePointerOriginal@@YGFKPAIPAD<V" ascii //weight: 1
        $x_2_3 = {2e 64 61 74 61 00 00 00 ?? 2f 01 00 00 d0 01 00 00 dc 00 00 00 c2 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 00 e0 2e 72 73 72 63}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_DDI_2147910063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.DDI!MTB"
        threat_id = "2147910063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 0f b6 82 ?? ?? ?? ?? 8b 4d fc 81 e1 03 00 00 80 79 05 49 83 c9 fc 41 0f b6 91 ?? ?? ?? ?? 33 c2 8b 4d fc 88 81 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BSDK_2147910253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BSDK!MTB"
        threat_id = "2147910253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 50 04 88 53 04 83 fe 04 0f 84 9d fe ff ff 0f b6 50 05 88 53 05 83 fe 05 0f 84 8d fe ff ff 0f b6 50 06 88 53 06 83 fe 06 0f 84 7d fe ff ff 0f b6 50 07 88 53 07}  //weight: 1, accuracy: High
        $x_1_2 = {55 89 e5 50 64 a1 30 00 00 00 89 45 fc 8b 45 fc 83 c4 04 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAU_2147910380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAU!MTB"
        threat_id = "2147910380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 64 ff 35 00 00 00 00 64 89 25 00 00 00 00 b8 ?? ?? ?? ?? b9 29 00 00 00 80 30 c7 40 49 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PNK_2147910952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PNK!MTB"
        threat_id = "2147910952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 01 8b 4d 08 32 04 11 83 3d 60 bd b7 6b 00 88 45 c8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d b4 8b 55 c4 8a 45 c8 88 04 11 81 3d 60 bd b7 6b 92 0f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_ERN_2147911048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.ERN!MTB"
        threat_id = "2147911048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ff 8b 04 95 40 b7 41 00 8b c8 81 e1 ff 00 00 00 c1 e8 08 33 04 8d 40 bb 41 00 83 c2 01 81 fa 00 08 00 00 89 04 95 3c bb 41 00 72 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAV_2147911850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAV!MTB"
        threat_id = "2147911850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 50 53 e8 01 00 00 00 cc}  //weight: 10, accuracy: High
        $x_1_2 = {58 89 c3 40 2d 00 a0 26 00 2d 00 82 0c 10 05 f7 81 0c 10 80 3b cc}  //weight: 1, accuracy: High
        $x_10_3 = {85 c9 74 0a 31 06 01 1e 83 c6 04 49 eb}  //weight: 10, accuracy: High
        $x_10_4 = {e8 00 00 00 00 58 05 58 00 00 00 80 38 e9 75 13}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_GIN_2147911976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.GIN!MTB"
        threat_id = "2147911976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 8b c6 be 03 00 00 00 33 d2 f7 f6 8b 45 10 83 c4 08 32 0c 10 8d 55 f8 51 52 e8 43 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YAW_2147912249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YAW!MTB"
        threat_id = "2147912249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 fc 5b 83 65 fc 00 c6 45 fc 5d 83 65 fc 00 c6 45 fc 5f 83 65 fc 00 c6 45 fc 61 83 65 fc 00 c6 45 fc 63}  //weight: 1, accuracy: High
        $x_1_2 = {8a 44 1e ff 84 c0 74 d0 30 04 1e eb cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHC_2147912430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHC!MTB"
        threat_id = "2147912430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0c 00 00 ?? ?? ?? ?? ?? 91 02 00 00 00 00 35 68}  //weight: 2, accuracy: Low
        $x_2_2 = {e9 00 00 00 00 6a 06 00 cc e8}  //weight: 2, accuracy: Low
        $x_2_3 = {b8 fd dd 44 53 f7 64 24 14 8b 44 24 14 81 6c 24 08 f0 06 bd 57 81 6c 24 38 f5 ?? 30 07 81 6c 24 28 7b e3 2f 6b 33 ff 81 3d ?? ?? d1 02 00 04 00 00 75 66}  //weight: 2, accuracy: Low
        $x_2_4 = {20 20 00 00 01 00 08 00 a8 08 00 00 02 00 30 30 00 00 01 00 20 00 a8 25 00 00 03 00 20 20 00 00 01 00 20 00 a8 10 00 00 04 00 10 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_THH_2147912842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.THH!MTB"
        threat_id = "2147912842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d dc 8b 75 e4 8a 44 1e ff 84 c0 74 ?? 30 04 1e eb ?? c7 45 fc 08 00 00 00 e8 ?? ?? ?? ?? c7 45 fc ff ff ff ff eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BBA_2147912843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BBA!MTB"
        threat_id = "2147912843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 f2 2b 4d fa 89 55 e7 89 45 e7 8b 4d e8 81 c3 a8 a2 00 00 8b 35 ?? ?? ?? ?? 89 d9 89 1d ?? ?? ?? ?? 89 c6 66 8b 4d e3 8b 5d fd 33 55 fa 8b 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_WIL_2147913142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.WIL!MTB"
        threat_id = "2147913142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f8 8d 5a 02 8b cb 66 0f be 02 66 31 01 8d 49 02 83 ef 01 75 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RRY_2147914180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RRY!MTB"
        threat_id = "2147914180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 fa 03 82 1c 01 00 00 a3 ?? ?? ?? ?? 8b 86 bc 00 00 00 2b 86 8c 00 00 00 2d ec 7e 1f 00 09 42 44 8b 8e d0 00 00 00 8b 86 b4 00 00 00 31 04 39 83 c7 04 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 81 b4 00 00 00 81 ff 54 03 00 00 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MBFH_2147914589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MBFH!MTB"
        threat_id = "2147914589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 40 00 a4 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 0c 11 40 00 0c 11 40 00 d0 10 40 00 78}  //weight: 1, accuracy: High
        $x_1_2 = {80 00 00 00 83 00 00 00 84 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6b 77 73 69 71 67 67 00 55 5a 00 00 55 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHM_2147915545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHM!MTB"
        threat_id = "2147915545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 09 00 00 e2 00 00 00 fe f5 01 00 00 00 00 03 19}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 4d f8 89 7d f8 e8 d3 ff ff ff 8a 45 f8 30 04 33 83 7d 08 0f 75 12}  //weight: 2, accuracy: High
        $x_2_3 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 38 9a 34 02 0f b7 05 3a 9a 34 02 25 ff 7f 00 00 c3}  //weight: 2, accuracy: High
        $x_1_4 = "Refenge" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHN_2147915546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHN!MTB"
        threat_id = "2147915546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0a 00 00 06 02 00 00 8c 4d 00 00 00 00 00 6a 6c}  //weight: 2, accuracy: Low
        $x_2_2 = {b8 6b 00 00 00 ba 72 00 00 00 66 a3 08 3e 8e 00 66 89 15 0c 3e 8e 00 b9 6e 00 00 00 ba 65 00 00 00 33 c0}  //weight: 2, accuracy: High
        $x_2_3 = {a8 25 00 00 07 00 18 18 00 00 01 00 20 00 88 09 00 00 08 00}  //weight: 2, accuracy: High
        $x_1_4 = "Sheathole" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHS_2147918387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHS!MTB"
        threat_id = "2147918387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 08 00 00 10 00 00 00 22 01 00 00 00 00 00 86 2e}  //weight: 2, accuracy: Low
        $x_1_2 = "csacsadhe.duckdns.org" wide //weight: 1
        $x_1_3 = "byfronbypass.html" wide //weight: 1
        $x_1_4 = "Arzgohi.mp3" wide //weight: 1
        $x_1_5 = "Microsoft Edge" wide //weight: 1
        $x_1_6 = {a8 25 00 00 03 00 28 28 00 00 01 00 20 00 68 1a 00 00 04 00 20 20 00 00 01 00 20 00 a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHT_2147918388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHT!MTB"
        threat_id = "2147918388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 04 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0a 00 00 3a 02 00 00 1c 22 00 00 00 00 00 6b a7 01}  //weight: 2, accuracy: Low
        $x_1_2 = "From Win32" wide //weight: 1
        $x_1_3 = "SecurityCenter2" wide //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "Install Date" ascii //weight: 1
        $x_1_6 = "MachineID" ascii //weight: 1
        $x_1_7 = "timeout" ascii //weight: 1
        $x_1_8 = "wallet.keys" ascii //weight: 1
        $x_1_9 = "t.me/bu77un" ascii //weight: 1
        $x_1_10 = "encrypted_key" ascii //weight: 1
        $x_1_11 = "PortNumber" ascii //weight: 1
        $x_1_12 = "DRIVE_REMOVABLE" ascii //weight: 1
        $x_1_13 = "powershell.exe" ascii //weight: 1
        $x_1_14 = "passwords.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHU_2147918398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHU!MTB"
        threat_id = "2147918398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 02 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 06 00 00 b0 00 00 00 70 00 00 00 00 00 00 50 11}  //weight: 2, accuracy: Low
        $x_1_2 = "CurrentVersion\\Explorer" wide //weight: 1
        $x_1_3 = "Happy BirthDay my's Boss" wide //weight: 1
        $x_1_4 = "musicvn.exe" wide //weight: 1
        $x_1_5 = "Logon User Name" wide //weight: 1
        $x_1_6 = "temp.zip" wide //weight: 1
        $x_1_7 = "HideFileExt" wide //weight: 1
        $x_1_8 = "System Restore" wide //weight: 1
        $x_1_9 = "MethCallEngine" ascii //weight: 1
        $x_2_10 = {a8 25 00 00 34 75 20 20 00 00 01 00 20 00 a8 10 00 00 35 75 10 10 00 00 01 00 20 00 68 04 00 00 36 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_KKV_2147920974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.KKV!MTB"
        threat_id = "2147920974"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 d1 0f b6 d2 89 55 08 8a 55 f0 02 55 08 02 55 f8 0f b6 d2 0f b6 5c ?? 04 8d 54 ?? 04 89 55 08 8b 55 0c 30 5c 16 ff 8b 55 08 8b 12 31 17 8b 7c 88 04 03 7d ec 8b 55 f4 31 3a 3b 75 10 0f 8c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_YTB_2147922251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.YTB!MTB"
        threat_id = "2147922251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 10 8b c8 e8 ?? ?? ff ff 6a 1e ff d7 83 ee 01 75 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_RHAI_2147922833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.RHAI!MTB"
        threat_id = "2147922833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0a 00 00 c0 1a 00 00 5c 12 00 00 00 00 00 ce e9 08}  //weight: 2, accuracy: Low
        $x_3_2 = "GOST" ascii //weight: 3
        $x_1_3 = "userPassword" ascii //weight: 1
        $x_3_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 3
        $x_1_5 = "ad04.png" wide //weight: 1
        $x_1_6 = "logic_sevice_id" wide //weight: 1
        $x_1_7 = "login_ip" wide //weight: 1
        $x_1_8 = "gtestnetwork" wide //weight: 1
        $x_1_9 = "T0R:" ascii //weight: 1
        $x_2_10 = {50 4b 03 04 14 00 00 00 08 00 27 8b 7e 4c b7 04 0e da 83 02 00 00 e3 03 00 00 06 00 00 00 30 31 2e 70 6e 67}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_AKX_2147924762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AKX!MTB"
        threat_id = "2147924762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 b8 8b 45 f0 8d 1c 02 8b 55 ec 8b 45 f0 01 d0 0f b6 30 8b 4d f0 ba 4f ec c4 4e 89 c8 f7 e2 89 d0 c1 e8 03 6b c0 1a 29 c1 89 c8 0f b6 44 05 96 31 f0 88 03}  //weight: 2, accuracy: High
        $x_1_2 = "JKH!xj+tv2<?VWE?+t6v?_rZ+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CDD_2147924928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CDD!MTB"
        threat_id = "2147924928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 d2 0f b6 5c 96 04 8d 54 96 04 89 95 ?? ?? fe ff 8b 95 ?? ?? fe ff 30 5c 3a ff 8b 95 ?? ?? fe ff 8b 1a 8b 95 ?? ?? fe ff 31 1a 8b 5c 86 04 03 9d ?? ?? fe ff 8b 95 ?? ?? fe ff 31 1a 3b 7d 10 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BSA_2147926177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BSA!MTB"
        threat_id = "2147926177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "nfhgbdxsvaglaxdmhekecaxahdfxqqdvgkcwwpektnyovmnjokbxwxcpptxpqbcwbrochvvmqueflgoevvwsxscr" ascii //weight: 10
        $x_5_2 = "xhxonfcarppkaruywgmvjqevmfxsyykbeavrysuxkiluvqkqvwjgysdforqgkmmukvjrpeirngoxrotsscgwocoyxe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptInject_PAFW_2147926204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PAFW!MTB"
        threat_id = "2147926204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {30 1f 41 8b 5d 0c 4f 3b 4d 08 0f}  //weight: 2, accuracy: High
        $x_2_2 = {f7 e1 8b c1 c1 ea 04 8d 14 92 c1 e2 02 2b c2 8b 55 0c 0f b6 04 10 2b c1 03 d8 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_TBM_2147927695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.TBM!MTB"
        threat_id = "2147927695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b fe 88 4c 24 38 88 4c 24 42 88 4c 24 47 c6 44 24 34 78 c6 44 24 35 61 88 54 24 3a c6 44 24 3e 66 c6 44 24 41 33 c6 44 24 43 97 c6 44 24 44 74 88 54 24 46 c6 44 24 40 95 c6 44 24 39 62 c7 44 24 10 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_BKL_2147928117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.BKL!MTB"
        threat_id = "2147928117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MyCallUpdate" ascii //weight: 1
        $x_1_2 = "Erro ao localizar a fun" ascii //weight: 1
        $x_1_3 = "ClassicIEDLL_64.dll" ascii //weight: 1
        $x_1_4 = "SaaSAPI.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_OPI_2147928125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.OPI!MTB"
        threat_id = "2147928125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 7c 24 10 89 44 24 0c 0f b6 04 30 88 04 37 8b 44 24 0c 88 0c 30 8b cf 0f b6 04 31 03 c2 0f b6 c0 8a 04 30 32 83 ?? ?? ?? ?? 88 83 00 50 1c 10 f6 c3 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MUC_2147928288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MUC!MTB"
        threat_id = "2147928288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c0 01 89 85 ?? ?? ff ff 8b 8d ?? ?? ff ff 3b 8d 08 f5 ff ff 73 50 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff 8b 85 b4 e3 ff ff 03 85 b8 f9 ff ff 8a 08 88 0a 56 81 ce d0 2d 00 00 81 e6 08 5e 00 00 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_WFZ_2147928871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.WFZ!MTB"
        threat_id = "2147928871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 1c 38 83 c7 04 0f af 5e 58 a1 ?? ?? ?? ?? 8b d3 c1 ea 10 88 14 01 b8 d8 f3 1b 00 ff 05 ?? ?? ?? ?? 8b d3 2b 86 b4 00 00 00 01 46 64 8b 8e 84 00 00 00 33 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 84 6b fc fe c1 ea 08 03 c1 a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_LM_2147928953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.LM!MTB"
        threat_id = "2147928953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 15 30 00 00 00 50 8f 42 08 8b 5d 0c 03 5b 3c 64 a1 30 00 00 00 8b 40 0c 8d 40 0c 8b 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_OIV_2147930143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.OIV!MTB"
        threat_id = "2147930143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d f8 83 c1 01 33 4d fc 2b c1 8b 55 f8 88 82 ?? ?? ?? ?? eb 18 8b 45 f4 0f be 08 51 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_PAGB_2147931021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.PAGB!MTB"
        threat_id = "2147931021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ReflectiveLoader" ascii //weight: 2
        $x_2_2 = "injection.dll" ascii //weight: 2
        $x_2_3 = "SeDebugPrivilege" ascii //weight: 2
        $x_1_4 = "Failed to open the target process" ascii //weight: 1
        $x_1_5 = "[+] Injected the DLL into process %lu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_WZV_2147931404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.WZV!MTB"
        threat_id = "2147931404"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 81 e3 a0 eb 00 00 81 eb 8e 1d 01 00 81 c3 69 cb 00 00 5b 8b 8d f4 f4 ff ff 89 8d 54 e2 ff ff c7 85 ?? ?? ff ff 00 00 00 00 eb 0f 8b 95 ?? ?? ff ff 83 c2 01 89 95 60 f9 ff ff 8b 85 60 f9 ff ff 3b 85 7c f4 ff ff 73 50 8b 8d 54 e2 ff ff 03 8d ?? ?? ff ff 8b 95 50 e2 ff ff 03 95 ?? ?? ff ff 8a 02 88 01 56 81 f6 fc 07 01 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_OIU_2147935216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.OIU!MTB"
        threat_id = "2147935216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 44 18 ff 24 0f 8b 55 f0 8a 54 32 ff 80 e2 0f 32 c2 88 45 f7 8d 45 fc e8 ?? ?? ?? ?? 8b 55 fc 8a 54 1a ff 80 e2 f0 8a 4d f7 02 d1 88 54 18 ff 46 8b 45 f0 e8 ?? ?? ?? ?? 3b f0 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CCJU_2147935376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CCJU!MTB"
        threat_id = "2147935376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 d0 31 cb 89 da 88 10 83 45 ec 01 8b 45 ?? ?? 45 ?? 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_LZT_2147938119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.LZT!MTB"
        threat_id = "2147938119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ce 83 e1 1f d3 e8 33 d2 b9 d0 01 00 00 89 45 f8 8b c6 f7 f1 8b 4d f8 8b c7 46 32 0c 02 8b 55 08 32 cb 88 4c 16 ?? d1 eb 83 fe 20 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_MDD_2147939307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.MDD!MTB"
        threat_id = "2147939307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b ce 83 e1 1f d3 e8 33 d2 b9 ?? ?? ?? ?? 89 45 f8 8b c6 f7 f1 8b 45 0c 8b 4d f8 46 32 0c 02 8b 55 08 32 cb 88 4c 16 ff d1 eb 83 fe 20 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_CCJZ_2147942572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.CCJZ!MTB"
        threat_id = "2147942572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {99 83 e2 1f 01 d0 c1 f8 05 83 e8 01 0f b6 44 05 ?? 31 c8 88 45 ?? c7 45}  //weight: 6, accuracy: Low
        $x_4_2 = {01 ca 0f b6 1a 8d 4d ?? 8b 55 ?? 01 ca 0f b6 12 31 da 88 10 83 45 ?? 01 83 7d ?? 03 7e}  //weight: 4, accuracy: Low
        $x_1_3 = "PAYLOAD_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptInject_AHB_2147946294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptInject.AHB!MTB"
        threat_id = "2147946294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {39 d2 74 01 ea 31 07 68 ?? ?? ?? ?? 8b 1c 24 83 c4 04 81 c7 04 00 00 00 49 39 d7 75 e3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

