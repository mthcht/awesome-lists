rule Trojan_Win32_Strab_CC_2147815679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.CC!MTB"
        threat_id = "2147815679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 0c 10 8b 85 [0-4] 33 c1 31 45 fc 81 3d [0-4] a3 01 00 00 75 1a}  //weight: 2, accuracy: Low
        $x_2_2 = {81 f9 4a 79 02 0f 7f 0d 41 81 f9 b2 78 6c 6d 0f 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_CD_2147815761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.CD!MTB"
        threat_id = "2147815761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 45 fc 8b 45 fc 8a 04 30 8b 0d [0-4] 88 04 0e}  //weight: 2, accuracy: Low
        $x_2_2 = {81 f9 4a 79 02 0f 7f 0d 41 81 f9 b2 97 76 67 0f 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_CE_2147817455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.CE!MTB"
        threat_id = "2147817455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 45 fc 8b 45 fc 8a 0c 30 8b 15 [0-4] 88 0c 16}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 60 4b da 26 7f 0c 40 3d b6 ad 81 5b 0f 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_CA_2147837739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.CA!MTB"
        threat_id = "2147837739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 74 24 10 0f b6 4c 24 1b 8b 54 24 28 0f af f1 8b 4c 24 2c b9 08 03 4a 59 2b ca f7 d6 f7 d1 33 f1 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? f7 d6 0f af f1 89 35 ?? ?? ?? ?? 48 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_SP_2147839349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.SP!MTB"
        threat_id = "2147839349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {8b 55 f8 83 c2 01 89 55 f8 83 7d f8 04 7d 1e 8b 45 f8 0f b6 4c 05 f4 51 8d 55 8c 52 8b 4d e0 e8 ?? ?? ?? ?? 8b 4d f8 88 44 0d f4 eb d3}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GCW_2147840109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GCW!MTB"
        threat_id = "2147840109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 d0 30 c8 20 d0 88 d5 80 f5 ?? 88 e1 20 e9 80 f4 ?? 20 e2 08 d1 88 c2 20 ca 30 c8 08 c2 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? f6 c2 ?? 0f 45 c1 89 45 ?? e9}  //weight: 10, accuracy: Low
        $x_1_2 = "\\Users\\Public\\Desktop\\error.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_RF_2147840151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.RF!MTB"
        threat_id = "2147840151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 f2 4e 88 95 37 ff ff ff 0f b7 05 ?? ?? ?? ?? 99 05 5b 0f d8 99 81 d2 54 73 0e 00 a3 ?? ?? ?? ?? 8b 45 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_RF_2147840151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.RF!MTB"
        threat_id = "2147840151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 8b 45 fc 33 d0 89 55 fc 8b 55 fc 8b f3 85 d2 74 03 8b 75 fc 8b 45 fc 99 f7 fe 8b 55 fc bf 05 00 00 00 0f af c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GFE_2147841665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GFE!MTB"
        threat_id = "2147841665"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 58 f6 ea 8a c8 8b 44 24 50 32 0d ?? ?? ?? ?? 2c 2a f6 2d ?? ?? ?? ?? f6 ac 24 ?? ?? ?? ?? 02 c8 88 4c 24 50 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_CPR_2147843455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.CPR!MTB"
        threat_id = "2147843455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 30 8b c6 83 e0 ?? 8a 88 ?? ?? ?? ?? 32 ca 0f b6 da 8d 04 19 8b 4d d0 88 04 31 ba ?? ?? ?? ?? b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GHN_2147845123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GHN!MTB"
        threat_id = "2147845123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1b c0 83 c0 01 8b 0d ?? ?? ?? ?? f7 d1 0f af c1 0f bf 55 98 33 95 ?? ?? ?? ?? f7 da 1b d2 83 c2 01 2b c2 a2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c9 05 ?? ?? ?? ?? 81 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GJU_2147850647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GJU!MTB"
        threat_id = "2147850647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 3d ?? ?? ?? ?? 03 ca 0f b6 c1 8b 4d 08 8a 84 05 ?? ?? ?? ?? 30 04 0e 46 3b 75 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GNG_2147851011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GNG!MTB"
        threat_id = "2147851011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 55 ff 8b 45 f0 03 45 f4 8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 88 ?? ?? ?? ?? ?? 8b 45 f4 83 c0 01 99 b9 ?? ?? ?? ?? f7 f9 89 55 f4}  //weight: 10, accuracy: Low
        $x_1_2 = "JKbtgdfd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GMP_2147892339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GMP!MTB"
        threat_id = "2147892339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c0 c8 03 32 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 46 01 99 41 f7 fb 8b f2 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPA_2147892997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPA!MTB"
        threat_id = "2147892997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c0 c8 03 32 83 ?? ?? ?? ?? 88 81 00 40 ?? ?? 8d 43 01 6a 0d 5b 99 f7 fb 41 8b da 3b ce 72 db}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GMX_2147893422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GMX!MTB"
        threat_id = "2147893422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c9 8a 81 ?? ?? ?? ?? c0 c8 03 32 83 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 43 01 6a 0d 99 5e f7 fe 41 b8 ?? ?? ?? ?? 8b da 3b c8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GMZ_2147893497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GMZ!MTB"
        threat_id = "2147893497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 ef 8a 86 ?? ?? ?? ?? c0 c0 ?? 32 81 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 89 d0 c1 e8 ?? c1 fa ?? 01 c2 8d 04 52 8d 04 82 f7 d8 01 c1 41 46}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_AMAB_2147895950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.AMAB!MTB"
        threat_id = "2147895950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 fb 8a 81 ?? ?? ?? ?? c0 c8 03 32 82 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 42 01 99 83 c1 03 f7 fb 8b f2 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_AMBC_2147896568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.AMBC!MTB"
        threat_id = "2147896568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 8a 81 ?? ?? ?? ?? c0 c8 03 32 86 ?? ?? ?? ?? 41 88 81 ?? ?? ?? ?? 8d 46 01 99 f7 fb 8b f2 81 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_CCEH_2147897089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.CCEH!MTB"
        threat_id = "2147897089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 88 45 fe 0f b6 4d ff c1 f9 ?? 0f b6 55 ff c1 e2 ?? 0b ca 0f b6 45 fe 33 c8 8b 55 f8 88 8a ?? ?? ?? ?? 8b 45 f0 83 c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 89 55 f0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_SPR_2147898786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.SPR!MTB"
        threat_id = "2147898786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 0f c0 c8 03 32 83 ?? ?? ?? ?? 88 04 0f 8d 43 01 bb ?? ?? ?? ?? 99 f7 fb 41 8b da 3b ce 72 df}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_AMBI_2147900116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.AMBI!MTB"
        threat_id = "2147900116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 c8 0f b6 4d ?? 31 c8 88 c1 8b 45 ?? 88 0c 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_AMBI_2147900116_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.AMBI!MTB"
        threat_id = "2147900116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 fe 0f b6 81 ?? ?? ?? ?? c0 c8 03 32 82 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 42 01 99 f7 fe}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_SPRJ_2147901320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.SPRJ!MTB"
        threat_id = "2147901320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {d1 e8 c1 e1 07 46 0b c8 03 cf 03 d1 0f be 3e 8b c2 85 ff 75}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_SPXP_2147902489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.SPXP!MTB"
        threat_id = "2147902489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 00 6a 00 ff d5 e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPE_2147904688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPE!MTB"
        threat_id = "2147904688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@TEMPDIR" ascii //weight: 1
        $x_1_2 = "DLLCALL" ascii //weight: 1
        $x_1_3 = "117+111+124+120+111+118+61+60\" , 10" ascii //weight: 1
        $x_1_4 = "96+115+124+126+127+107+118+75+118+118+121+109" ascii //weight: 1
        $x_1_5 = "110+129+121+124+110" ascii //weight: 1
        $x_1_6 = "58+130+62+58\" , 10" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GP_2147904695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GP!MTB"
        threat_id = "2147904695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "vp}ypw>=\" , 11" ascii //weight: 5
        $x_5_5 = "nhuqho65\" , 3" ascii //weight: 5
        $x_5_6 = "smzvmt;:\" , 8" ascii //weight: 5
        $x_5_7 = "nyNyy|p\" , 13" ascii //weight: 5
        $x_5_8 = "uo|xov=<\" , 10" ascii //weight: 5
        $x_7_9 = {4e 6c 77 77 62 74 79 6f 7a e2 80 9a 5b 7d 7a 6e}  //weight: 7, accuracy: High
        $x_7_10 = "YluwxdoDoorf" ascii //weight: 7
        $x_7_11 = "^qz|}itIttwk" ascii //weight: 7
        $x_7_12 = "Pnyydv" ascii //weight: 7
        $x_7_13 = "Mkvvasxny" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_5_*))) or
            ((2 of ($x_7_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_5_*))) or
            ((3 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_GPF_2147904984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPF!MTB"
        threat_id = "2147904984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "deerlettuce.xyz/pan.php?pe" ascii //weight: 5
        $x_2_2 = "forcereaction.xyz/pin.php?pe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPF_2147904984_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPF!MTB"
        threat_id = "2147904984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\"53733334330363438423730333038423736304338423736314338423645303838423745323038423336333834373138373546333" ascii //weight: 2
        $x_2_2 = "\"37384243353546354535423539354135444333353535323531353335363537384236433234314338354544373434333842343533" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPG_2147904986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPG!MTB"
        threat_id = "2147904986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "eklt_r-8\" , 6" ascii //weight: 5
        $x_7_5 = "PolzogfGfrii" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPH_2147905023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPH!MTB"
        threat_id = "2147905023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "lfsofm43\" , 1" ascii //weight: 5
        $x_5_5 = "cmjv]t+:\" , 8" ascii //weight: 5
        $x_5_6 = "bniw\\u*;\" , 9" ascii //weight: 5
        $x_7_7 = "WjsuvbmBmmpd" ascii //weight: 7
        $x_7_8 = "Mri}ljcJcufl" ascii //weight: 7
        $x_7_9 = "Nqj|midIdtgk" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_7_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_7_*) and 2 of ($x_5_*))) or
            ((2 of ($x_7_*) and 1 of ($x_1_*))) or
            ((2 of ($x_7_*) and 1 of ($x_5_*))) or
            ((3 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_KAA_2147905177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.KAA!MTB"
        threat_id = "2147905177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEINSTALL" ascii //weight: 1
        $x_1_2 = "@TEMPDIR" ascii //weight: 1
        $x_1_3 = "DLLCALL" ascii //weight: 1
        $x_5_4 = "QnmypfgFgqjh\" , 5" ascii //weight: 5
        $x_7_5 = "fgqRniij|Kwjh" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPX_2147905239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPX!MTB"
        threat_id = "2147905239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 5, accuracy: Low
        $x_5_3 = "FILEREAD ( FILEOPEN ( @TEMPDIR &" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Strab_GPX_2147905239_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPX!MTB"
        threat_id = "2147905239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 5, accuracy: Low
        $x_5_3 = {46 00 49 00 4c 00 45 00 52 00 45 00 41 00 44 00 [0-3] 28 00 [0-3] 46 00 49 00 4c 00 45 00 4f 00 50 00 45 00 4e 00 [0-3] 28 00 [0-3] 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00}  //weight: 5, accuracy: Low
        $x_5_4 = {46 49 4c 45 52 45 41 44 [0-3] 28 [0-3] 46 49 4c 45 4f 50 45 4e [0-3] 28 [0-3] 40 54 45 4d 50 44 49 52}  //weight: 5, accuracy: Low
        $x_5_5 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 [0-3] 28 00 [0-31] 28 00}  //weight: 5, accuracy: Low
        $x_5_6 = {44 6c 6c 43 61 6c 6c [0-3] 28 [0-31] 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Strab_NA_2147906029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NA!MTB"
        threat_id = "2147906029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "colliquefaction" ascii //weight: 1
        $x_1_2 = "antiprimer" ascii //weight: 1
        $x_1_3 = "MOUSECLICKDRAG" ascii //weight: 1
        $x_1_4 = "FILEINSTALL" ascii //weight: 1
        $x_1_5 = "MOUSEGETCURSOR" ascii //weight: 1
        $x_2_6 = "FUNC V31WL" ascii //weight: 2
        $x_2_7 = "= BITXOR (" ascii //weight: 2
        $x_2_8 = "&= CHR" ascii //weight: 2
        $x_2_9 = "@tempdir" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_AMMF_2147907383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.AMMF!MTB"
        threat_id = "2147907383"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "BinaryToString(\"\"0x6B65726E656C3332\"\")" ascii //weight: 1
        $x_1_4 = "BinaryToString(\"\"0x5669727475616C416C6C6F63\"\")" ascii //weight: 1
        $x_1_5 = "BinaryToString(\"\"0x64776F7264\"\")" ascii //weight: 1
        $x_1_6 = "EXECUTE" ascii //weight: 1
        $x_1_7 = "ToString(\"\"0x43616C6C57696E646F7750726F6\"" ascii //weight: 1
        $x_1_8 = "ENVGET ( \"d2gj2NKUqDy\" )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Strab_NB_2147907458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NB!MTB"
        threat_id = "2147907458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "spiketop" ascii //weight: 5
        $x_5_2 = "unrosined" ascii //weight: 5
        $x_1_3 = "BITXOR" ascii //weight: 1
        $x_1_4 = "&= CHR" ascii //weight: 1
        $x_1_5 = "EXECUTE" ascii //weight: 1
        $x_1_6 = "tempdir" ascii //weight: 1
        $x_1_7 = "FILEINSTALL" ascii //weight: 1
        $x_1_8 = "MOUSECLICK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_NC_2147907837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NC!MTB"
        threat_id = "2147907837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Fil\" & \"eOp\" & \"en(@te\" & \"mpdir" ascii //weight: 5
        $x_5_2 = "Stri\" & \"ngRepl\" & \"ace" ascii //weight: 5
        $x_1_3 = "EXECUTE ( \"DllStruct\" & \"Create(Chr(" ascii //weight: 1
        $x_1_4 = "EXECUTE ( \"DllCallAd\" & \"dress(Chr(" ascii //weight: 1
        $x_1_5 = "REGENUMKEY" ascii //weight: 1
        $x_1_6 = "FILEINSTALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_SPDB_2147908221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.SPDB!MTB"
        threat_id = "2147908221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 d2 fd 43 03 00 81 c2 c3 9e 26 00 89 15 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 30 83 ff 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPJ_2147908512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPJ!MTB"
        threat_id = "2147908512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d a4 24 00 00 00 00 8b 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 14 1e 83 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPK_2147908513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPK!MTB"
        threat_id = "2147908513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" &" ascii //weight: 1
        $x_1_4 = "D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Strab_NE_2147909351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NE!MTB"
        threat_id = "2147909351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" &" ascii //weight: 2
        $x_2_2 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" &" ascii //weight: 2
        $x_2_3 = "EXECUTE ( \"D\" & \"l\" & \"l\" & \"C\" & \"a\" & \"l\" & \"l\" &" ascii //weight: 2
        $x_1_4 = "t\" & \"e\" & \"m\" & \"p\" & \"d\" & \"i\" &" ascii //weight: 1
        $x_1_5 = "eKybebKslp" ascii //weight: 1
        $x_1_6 = "Uc8py64bkFJQkAtUq" ascii //weight: 1
        $x_1_7 = "WINKILL ( \"0dvswmiqeRGjVMcHH91O" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Strab_GPBX_2147911104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPBX!MTB"
        threat_id = "2147911104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 5, accuracy: Low
        $x_1_3 = "EXECUTE ( \"F\" & \"ileRe\" & \"ad(FileO\" & \"pen(" ascii //weight: 1
        $x_1_4 = "FileRead(FileOpen(@tempdir" ascii //weight: 1
        $x_1_5 = "EXECUTE ( \"D\" & \"ll\" & \"Call(" ascii //weight: 1
        $x_1_6 = "D\" & \"ll\" & \"Call(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_GPCX_2147911583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPCX!MTB"
        threat_id = "2147911583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 [0-3] 28 00 [0-3] 22 00 46 00 [0-5] 69 00 [0-5] 6c 00 [0-5] 65 00 [0-5] 52 00 [0-5] 65 00 [0-5] 61 00 [0-5] 64 00 28 00 46 00 [0-5] 69 00 [0-5] 6c 00 [0-5] 65 00 [0-5] 4f 00 [0-5] 70 00 [0-5] 65 00 [0-5] 6e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {45 58 45 43 55 54 45 [0-3] 28 [0-3] 22 46 [0-5] 69 [0-5] 6c [0-5] 65 [0-5] 52 [0-5] 65 [0-5] 61 [0-5] 64 28 46 [0-5] 69 [0-5] 6c [0-5] 65 [0-5] 4f [0-5] 70 [0-5] 65 [0-5] 6e}  //weight: 1, accuracy: Low
        $x_1_5 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 [0-3] 28 00 [0-31] 28 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6c 6c 43 61 6c 6c [0-3] 28 [0-31] 28}  //weight: 1, accuracy: Low
        $x_1_7 = {44 00 4c 00 4c 00 53 00 54 00 52 00 55 00 43 00 54 00 43 00 52 00 45 00 41 00 54 00 45 00 [0-3] 28 00 [0-31] 28 00}  //weight: 1, accuracy: Low
        $x_1_8 = {44 4c 4c 53 54 52 55 43 54 43 52 45 41 54 45 [0-3] 28 [0-31] 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Strab_GPDX_2147911767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPDX!MTB"
        threat_id = "2147911767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 1, accuracy: Low
        $x_1_3 = "EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"e\" & \"a\" & \"d\" & \"(\" & \"F" ascii //weight: 1
        $x_1_4 = "EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"R\" & \"e\" & \"p\" & \"l\" & \"a\" & \"c\" & \"e" ascii //weight: 1
        $x_1_5 = {44 00 6c 00 6c 00 43 00 61 00 6c 00 6c 00 [0-3] 28 00 [0-31] 28 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6c 6c 43 61 6c 6c [0-3] 28 [0-31] 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Strab_NF_2147915265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NF!MTB"
        threat_id = "2147915265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 45 00 4e 00 56 00 47 00 45 00 54 00 20 00 28 00 20 00 22 00 54 00 22 00 20 00 26 00 20 00 22 00 45 00 22 00 20 00 26 00 20 00 22 00 4d 00 22 00 20 00 26 00 20 00 22 00 50 00 22 00 20 00 29 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 45 4e 56 47 45 54 20 28 20 22 54 22 20 26 20 22 45 22 20 26 20 22 4d 22 20 26 20 22 50 22 20 29 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"DllCall(" ascii //weight: 2
        $x_2_4 = "&= EXECUTE ( \"Chr(BitXOR(Asc(StringMid($" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_GPEX_2147915857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.GPEX!MTB"
        threat_id = "2147915857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 5, accuracy: Low
        $x_5_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 5, accuracy: Low
        $x_3_3 = "EXECUTE ( \"FileRead(FileOpen(@TempDir  &" ascii //weight: 3
        $x_2_4 = {45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00 20 00 22 00 44 00 6c 00 6c 00 43 00 22 00 20 00 26 00 20 00 22 00 61 00 6c 00 6c 00 28 00 [0-16] 28 00 22 00}  //weight: 2, accuracy: Low
        $x_2_5 = {45 58 45 43 55 54 45 20 28 20 22 44 6c 6c 43 22 20 26 20 22 61 6c 6c 28 [0-16] 28 22}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NH_2147916583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NH!MTB"
        threat_id = "2147916583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "EXECUTE ( \"F\" & \"ile\" & \"Read(Fi\" & \"leO\" & \"pen(@TempDir  &" ascii //weight: 2
        $x_2_4 = "= EXECUTE ( \"A\" & \"sc(Str\" & \"ingM\" & \"id" ascii //weight: 2
        $x_2_5 = "&= EXECUTE ( \"Ch\" & \"r(" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NH_2147916583_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NH!MTB"
        threat_id = "2147916583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"F\" & \"i\" & \"l\" & \"e\" & \"R\" & \"ea\" & \"d(File\" & \"Op\" & \"en(@Te\" & \"mpDir &" ascii //weight: 2
        $x_2_4 = "= EXECUTE ( \"S\" & \"t\" & \"r\" & \"ing\" & \"Re\" & \"ver\" &" ascii //weight: 2
        $x_2_5 = "&= EXECUTE ( \"C\" & \"h\" & \"r(2\" & \"5\" & \"6 - A\" & \"s\" & \"c(S\" & \"t\" & \"r\" & \"in\" & \"gM" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NJ_2147916939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NJ!MTB"
        threat_id = "2147916939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"A\" & \"sc(Str\" & \"ingM\" & \"id" ascii //weight: 2
        $x_2_4 = "&= EXECUTE ( \"Ch\" & \"r(" ascii //weight: 2
        $x_2_5 = "xdoDoorf" ascii //weight: 2
        $x_2_6 = "gzrug" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NI_2147917723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NI!MTB"
        threat_id = "2147917723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"FileRead(FileOpen(@TempDir  &" ascii //weight: 2
        $x_2_4 = "= EXECUTE ( \"StringReplace(" ascii //weight: 2
        $x_2_5 = "= EXECUTE ( \"DllCall" ascii //weight: 2
        $x_2_6 = "= EXECUTE ( \"Mod((Asc(StringMid(" ascii //weight: 2
        $x_2_7 = "&= EXECUTE ( \"Chr(BitXOR(" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_2_*))) or
            ((2 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NO_2147917730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NO!MTB"
        threat_id = "2147917730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"Asc(StringMid(" ascii //weight: 2
        $x_2_4 = "&= EXECUTE ( \"Chr(" ascii //weight: 2
        $x_2_5 = "TkpvscjCjnme" ascii //weight: 2
        $x_2_6 = "igppcn14" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NO_2147917730_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NO!MTB"
        threat_id = "2147917730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"A\" & \"sc(Str\" & \"ingM\" & \"id(" ascii //weight: 2
        $x_2_4 = "&= EXECUTE ( \"Ch\" & \"r" ascii //weight: 2
        $x_2_5 = "pjwsjq873iqq" ascii //weight: 2
        $x_2_6 = "mfsiqj" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NM_2147918299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NM!MTB"
        threat_id = "2147918299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "EXECUTE ( \"A\" & \"s\" & \"c\" & \"(\" & \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d(" ascii //weight: 2
        $x_2_4 = "&= EXECUTE ( \"C\" & \"h\" & \"r\" &" ascii //weight: 2
        $x_2_5 = "JsvzlOhuksl" ascii //weight: 2
        $x_2_6 = "rlyuls:95kss" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NQ_2147919183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NQ!MTB"
        threat_id = "2147919183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = "= EXECUTE ( \"Stri\" & \"ngM\" & \"id" ascii //weight: 2
        $x_2_4 = "&= EXECUTE ( \"C\" & \"hr(D\" & \"ec" ascii //weight: 2
        $x_2_5 = "6BR65V72X6EL65E6CQ33U32A2ER64P6CY6CX" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NS_2147919606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NS!MTB"
        threat_id = "2147919606"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = {3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 53 00 54 00 45 00 50 00 20 00 33 00}  //weight: 2, accuracy: Low
        $x_2_4 = {3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-48] 20 29 20 53 54 45 50 20 33}  //weight: 2, accuracy: Low
        $x_2_5 = "&= EXECUTE ( \"C\" & \"h\" & \"r\" & \"(\" & \"D\" & \"e\" & \"c\" & \"(\" &" ascii //weight: 2
        $x_2_6 = "&= STRINGLEFT ( STRINGTRIMLEFT (" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NT_2147919607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NT!MTB"
        threat_id = "2147919607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = {3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 53 00 54 00 45 00 50 00 20 00 33 00}  //weight: 2, accuracy: Low
        $x_2_4 = {3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-48] 20 29 20 53 54 45 50 20 33}  //weight: 2, accuracy: Low
        $x_2_5 = "= EXECUTE ( \"S\" & \"t\" & \"r\" & \"i\" & \"n\" & \"g\" & \"M\" & \"i\" & \"d\" & \"(\" &" ascii //weight: 2
        $x_2_6 = "&= EXECUTE ( \"C\" & \"h\" & \"r\" & \"(\" & \"D\" & \"e\" & \"c\" & \"(\" &" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NR_2147920142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NR!MTB"
        threat_id = "2147920142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 4, accuracy: Low
        $x_4_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 4, accuracy: Low
        $x_2_3 = {3d 00 20 00 31 00 20 00 54 00 4f 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 4c 00 45 00 4e 00 20 00 28 00 20 00 24 00 [0-48] 20 00 29 00 20 00 53 00 54 00 45 00 50 00 20 00 33 00}  //weight: 2, accuracy: Low
        $x_2_4 = {3d 20 31 20 54 4f 20 53 54 52 49 4e 47 4c 45 4e 20 28 20 24 [0-48] 20 29 20 53 54 45 50 20 33}  //weight: 2, accuracy: Low
        $x_2_5 = "= EXECUTE ( \"Stri\" & \"ngM\" & \"id" ascii //weight: 2
        $x_2_6 = "&= EXECUTE ( \"C\" & \"hr(D\" & \"ec" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Strab_NFA_2147933491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Strab.NFA!MTB"
        threat_id = "2147933491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Strab"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 49 00 4c 00 45 00 49 00 4e 00 53 00 54 00 41 00 4c 00 4c 00 20 00 28 00 20 00 22 00 [0-47] 22 00 20 00 2c 00 20 00 40 00 54 00 45 00 4d 00 50 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 00 22 00 20 00 2c 00 20 00 31 00 20 00 29 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 49 4c 45 49 4e 53 54 41 4c 4c 20 28 20 22 [0-47] 22 20 2c 20 40 54 45 4d 50 44 49 52 20 26 20 22 5c 00 22 20 2c 20 31 20 29}  //weight: 2, accuracy: Low
        $x_1_3 = {49 00 46 00 20 00 28 00 20 00 24 00 [0-31] 20 00 41 00 4e 00 44 00 20 00 24 00 [0-31] 20 00 3d 00 20 00 24 00 [0-31] 20 00 29 00 20 00 4f 00 52 00 20 00 28 00 20 00 4e 00 4f 00 54 00 20 00 24 00 [0-31] 20 00 41 00 4e 00 44 00 20 00 24 00 [0-31] 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00 20 00 3d 00 20 00 24 00 [0-31] 20 00 28 00 20 00 24 00 [0-31] 20 00 29 00 20 00 29 00 20 00 54 00 48 00 45 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_4 = {49 46 20 28 20 24 [0-31] 20 41 4e 44 20 24 [0-31] 20 3d 20 24 [0-31] 20 29 20 4f 52 20 28 20 4e 4f 54 20 24 [0-31] 20 41 4e 44 20 24 [0-31] 20 28 20 24 [0-31] 20 29 20 3d 20 24 [0-31] 20 28 20 24 [0-31] 20 29 20 29 20 54 48 45 4e}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 45 00 47 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 28 00 20 00 22 00 48 00 4b 00 43 00 55 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 22 00 20 00 2c 00 20 00 22 00 [0-31] 22 00 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 47 44 45 4c 45 54 45 20 28 20 22 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 22 20 2c 20 22 [0-31] 22 20 29}  //weight: 1, accuracy: Low
        $x_1_7 = "D528210520llS528210520tru528210520ct528210520Cre528210520ate" ascii //weight: 1
        $x_1_8 = "Fil528210520eRe528210520ad" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

