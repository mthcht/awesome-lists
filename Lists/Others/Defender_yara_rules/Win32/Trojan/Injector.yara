rule Trojan_Win32_Injector_B_2147626549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.B"
        threat_id = "2147626549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 c4 f8 8b c8 33 d2 89 55 f8 89 4d fc 8b 45 fc 03 45 f8 89 c7 80 37 ?? 90 42 81 fa ?? ?? 00 00 75 e5 59 59 5d}  //weight: 1, accuracy: Low
        $x_1_2 = "omjB6EN11Lv8RQUsr8XZSflhh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Injector_X_2147651842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.X"
        threat_id = "2147651842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tr7qet7q6wte71276r8" ascii //weight: 1
        $x_1_2 = {33 db 8d 0c 5d ?? ?? ?? ?? 91 2d [0-16] 3b c2 75 ?? 8d 92 6f 8c ff ff eb ?? 2b 15 ?? ?? ?? ?? 3b c2 76 [0-48] 5d ff e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_AB_2147655957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.AB"
        threat_id = "2147655957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 00 54 45 4d 50 c7 40 04 5c 78 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 52 75 6e 20 2f 76 20 6d 73 6d 6d 73 67 72 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 00 63 74 66 6d 6f 6e 00 00 00 63 6d 64 20 2f 63 20 52 45 47 20 41 44 44 20 48 4b 43 55}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 0a 47 6f 74 3a 20 25 73 0a 00 71 71 71 00 77 69 6e 64 69 72 00 73 65 72 76 69 63 65 73 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = "There's no room for a new section :(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_AK_2147658636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.AK"
        threat_id = "2147658636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 70 01 8a 08 40 3a cb 75 f9 2b c6 50 57 8d 4c 24 28 e8 ?? ?? ?? ?? c6 44 24 60 02}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 8d 4c 24 18 51 68 03 01 00 00 ff d0 85 c0 74 ?? 8b 0d ?? ?? ?? ?? 33 c0 c6 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_AN_2147659626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.AN"
        threat_id = "2147659626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 95 fc fe ff ff 8b 42 50 50 8b 4d 10 51 8b 55 08 8b 02 50 ff 95 ?? ?? ?? ?? 6a 00 8b 8d fc fe ff ff 8b 51 54 52 8b 45 0c 50 8b 4d 10 51 8b 55 08 8b 02 50}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 01 89 8d 64 fd ff ff 8b 95 fc fe ff ff 0f b7 42 06 39 85 64 fd ff ff 7d 58 8b 8d 68 fd ff ff 8b 51 3c 8b 45 0c 8d 8c 10 f8 00 00 00 8b 95 64 fd ff ff 6b d2 28 03 ca 89 8d 60 fd ff ff 6a 00 8b 85 60 fd ff ff 8b 48 10 51 8b 95 60 fd ff ff 8b 45 0c 03 42 14 50 8b 8d 60 fd ff ff 8b 55 10 03 51 0c 52 8b 45 08 8b 08 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_AJ_2147660364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.AJ"
        threat_id = "2147660364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /C PING 127.0.0.1 -n 5 & del /F /Q" ascii //weight: 1
        $x_1_2 = "cmd.exe /C PING 127.0.0.1 -n 5 & del /F /Q" wide //weight: 1
        $x_1_3 = "Local\\%p" ascii //weight: 1
        $x_1_4 = "Local\\%p" wide //weight: 1
        $x_1_5 = "avpNexe" ascii //weight: 1
        $x_1_6 = {b8 68 58 4d 56 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56}  //weight: 1, accuracy: High
        $x_1_7 = {75 03 83 c0 20 88 06 46 80 3e 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Injector_BC_2147694221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.BC"
        threat_id = "2147694221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "86!85!49!192!100!139!112!48!139!118!12!139!118!28!139!110!8!139!126!32!139!54!56!71!24!117!243" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_BH_2147708716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.BH!bit"
        threat_id = "2147708716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 5c 38 ff 33 5d e4 8b 55 f0 8b c3 e8 ?? ?? ?? ?? 8b d8 8d 45 d4 8b d3 e8 ?? ?? ?? ?? 8b 55 d4 8d 45 ec e8 ?? ?? ?? ?? 8b 45 e4 89 45 f0 83 c6 02 8b 45 fc e8 ?? ?? ?? ?? 3b f0 7c 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YB_2147709398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YB!bit"
        threat_id = "2147709398"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 85 ?? ?? ff ff 8a 00 32 84 95 f4 fb ff ff 8b 4d 08 03 8d ?? ?? ff ff 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_BI_2147709405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.BI!bit"
        threat_id = "2147709405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d0 89 95 ?? ?? ff ff db 85 ?? ?? ff ff de c1 e8 ?? ?? 00 00 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ff ff 88 01 18 00 8b 95 ?? ?? ff ff 33 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 2b 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_BJ_2147709418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.BJ!bit"
        threat_id = "2147709418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 83 f1 ?? 8b ?? ?? 6b c0 ?? 99 be}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_BK_2147709419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.BK!bit"
        threat_id = "2147709419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 fb 8b 7c ?? ?? 31 fb 33 5c ?? ?? 8b 7c ?? ?? 31 fb 89 5c ?? ?? 68 01 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YC_2147709648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YC!bit"
        threat_id = "2147709648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f1 0f be 92 ?? ?? ?? ?? 8b 45 08 03 45 ?? 0f b6 08 33 ca 8b 55 08 03 55 ?? 88 0a e8 ?? ?? ?? ?? 8b 4d 08 03 4d ?? 0f b6 11 33 d0 8b 45 08 03 45 ?? 88 10 8b 4d 08 03 4d ?? 8b 55 08 03 55 ?? 8a 02 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YE_2147709856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YE!bit"
        threat_id = "2147709856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$GKEY = DLLSTRUCTGETDATA ( $DECOMPILE_STRUCT , \"CALG_KEY\" )" wide //weight: 1
        $x_1_2 = "$INJECTION_PATH = DLLSTRUCTGETDATA ( $DECOMPILE_STRUCT , \"INJECTION_PATH\" )" wide //weight: 1
        $x_1_3 = "$INJECTION_PATH = CALL ( \"__DECRYPTE\" , $INJECTION_PATH )" wide //weight: 1
        $x_1_4 = "$INJECTION_PATH = EXECUTE ( $INJECTION_PATH )" wide //weight: 1
        $x_1_5 = "CALL ( \"__RUNPE\" , $SHELLCODE_RUNPE , $PE_IMAGE , $INJECTION_PATH )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YL_2147710122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YL!bit"
        threat_id = "2147710122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 73 05 8d 6c 24 10 2b ee 8a 06 84 c0 74 11 32 c2 2a c1 fe c8 88 04 2e 41 46 3b cf 72 eb eb 03}  //weight: 2, accuracy: High
        $x_2_2 = {8a 49 02 8a 15 ?? ?? ?? ?? 8b f8 33 c0 55 02 ca 30 0c 30 8b 0d ?? ?? ?? ?? 8a 49 02 0f b6 e9 40 81 c5 ?? ?? ?? ?? 3b c5 76 e4}  //weight: 2, accuracy: Low
        $x_2_3 = {8b ff 8a 81 ?? ?? ?? ?? 84 c0 74 11 32 c2 2a c1 fe c8 88 44 0c 08 41 3b ce 72 e7 eb 07 c6 05 ?? ?? ?? ?? 00}  //weight: 2, accuracy: Low
        $x_1_4 = {83 78 14 00 75 3b 83 78 18 00 75 35 6a 00 6a 00 6a 11 6a fe ff 15 ?? ?? 40 00 8b 0e 89 0d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = "FUCK OFF!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YQ_2147710493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YQ!bit"
        threat_id = "2147710493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 89 45 ?? 6a 0c 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 0c 89 45 ?? 6a 08 68 ?? ?? 40 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 83 c4 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 0f be 0c 10 8b 95 ?? ?? ff ff 33 c0 8a 84 15 ?? ?? ff ff 8b 95 ?? ?? ff ff 03 d1 03 c2 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 89 85 ?? ?? ff ff 8b 85 ?? ?? ff ff 8a 8c 05 ?? ?? ff ff 88 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 8a 8c 05 ?? ?? ff ff 88 8c 15 ?? ?? ff ff 8b 95 ?? ?? ff ff 8a 85 ?? ?? ff ff 88 84 15 ?? ?? ff ff e9}  //weight: 1, accuracy: Low
        $x_1_3 = {43 75 72 72 65 6e 74 55 73 65 72 00 73 61 6e 64 00 00 00 00 76 6d 77 61 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YG_2147710755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YG!bit"
        threat_id = "2147710755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 40 18 83 ec 10 56 57 be ?? ?? ?? ?? a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 0f b6 05 00 10 40 00 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 85 c0 74 17 be ?? ?? ?? ?? e8 ?? ?? ?? ?? 50 6a 01 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0a 84 c9 74 15 32 0e 2a 4d fc fe c9 ff 45 fc 88 0c 10 42 39 7d fc 72 e7 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YO_2147711072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YO!bit"
        threat_id = "2147711072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 40 83 f8 ?? 7c dd 1c 00 8a 90 ?? ?? ?? ?? 32 d1 41 81 e1 ff 00 00 80 88 54 04 14 79 08 49 81 c9 00 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d1 81 e2 ?? ?? ?? ?? 79 05 4a 83 ?? ?? 42 f7 da 1a d2 bf ?? ?? ?? ?? 80 e2 ?? fe c2 8a c2 f6 e9 8a d8 8b c1 99 f7 ff 8a 82 ?? ?? ?? ?? 2a d8 8a 04 31 02 c3 88 04 31 8b ?? ?? ?? 41 3b c8 7c bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_BH_2147711101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.BH"
        threat_id = "2147711101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {df e0 f6 c4 ?? 75 ed (d0|d1) d8 dd 05 c0 30 40 00 e8 a3 08 00 00 33 f6 8a d8 89 75 fc bf 20 30 40 00 db 45 fc dc 1d c0 25 40 00 df e0 f6 c4 41 75 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YH_2147711328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YH!bit"
        threat_id = "2147711328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8b ?? 08 68 60 e8 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {55 89 e5 8b ?? 08 c7 ?? 60 e8 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {55 89 e5 8b ?? 08 c7 ?? 39 97 29 1f 81 ?? 59 7f 29 1f}  //weight: 1, accuracy: Low
        $x_5_4 = {89 c3 be 20 2b 40 00 81 fe 20 2b 40 00 73 0d ff 16 83 c6 04 81 fe 20 2b 40 00 72 f3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Injector_YR_2147711330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YR!bit"
        threat_id = "2147711330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dfsUU1" ascii //weight: 1
        $x_1_2 = {8b 5c 24 10 33 5c 24 14 33 5c 24 ?? 33 5c 24 0c 8b 7c 24 04 [0-16] 6b ff [0-32] 31 fb 89 5c 24 10}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5c 24 0c 83 c3 ?? 89 5c 24 0c 8b 5c 24 0c 8b 7c 24 ?? 83 c7 fe 39 fb 0f 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YV_2147711331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YV!bit"
        threat_id = "2147711331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 54 0e ff 8b 35 ?? ?? ?? ?? 7c e7 0d 00 8b 15 ?? ?? ?? ?? 41 3b cf 8a 54 0a ff}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 08 75 cd 2e 00 8b 35 ?? ?? ?? ?? 33 d2 8a 5c 0e ff f7 f7 49 8a 04 16 88 1c 16 8b 15 ?? ?? ?? ?? 88 04 0a c1 45 08 07 8b 45 08 2b c7 2d ?? ?? ?? ?? 85 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ZD_2147712304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ZD!bit"
        threat_id = "2147712304"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a0 34 30 40 00 ?? d8 88 45 ff 89 5d f8 db 45 f8 dc 1d e8 20 40 00 df e0 9e 76 15 dd 05 e0 20 40 00 90 51 8d 85 ?? ?? ff ff dd 1c 24 ff d0 59 59 8a 83 20 30 40 00 8d 8c 1d ?? ?? ff ff 32 45 ff 3c 3a 89 01 77 04 fe c8 88 01 43 eb bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ZO_2147712629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ZO!bit"
        threat_id = "2147712629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 03 95 ?? ?? ?? ff 8a 02 88 01 8b 4d f8 83 c1 01 89 4d f8 e9 ?? ?? ?? ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 8b 02 33 85 ?? ?? ?? ff 8b 4d f8 89 01 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ZY_2147714856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ZY!bit"
        threat_id = "2147714856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 e4 4b c6 45 e5 65 c6 45 e6 72 c6 45 e7 6e c6 45 e8 65 c6 45 e9 6c c6 45 ea 33 c6 45 eb 32 c6 45 ec 2e c6 45 ed 64 c6 45 ee 6c c6 45 ef 6c}  //weight: 1, accuracy: High
        $x_1_2 = {88 19 8b 4d ?? 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 ?? 8b 45 ?? 3b 45 ?? 72 ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ZS_2147716108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ZS!bit"
        threat_id = "2147716108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 37 83 c7 ?? f7 d6 f8 83 de ?? c1 ce ?? d1 c6 01 c6 8d 76 ff 29 c0 29 f0 f7 d8 c1 c0 ?? d1 c8 56 8f 03 83 c3 04 83 c2 fc 85 d2 75 d0}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 8b 15 50 70 46 00 52 ff d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ZV_2147716109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ZV!bit"
        threat_id = "2147716109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8d 05 c4 70 46 00 ff 10 0b 00 68 ?? ?? ?? ?? 8b 3c ?? c6 07 4c}  //weight: 1, accuracy: Low
        $x_1_2 = {23 19 83 e9 ?? f7 d3 8d 5b ?? c1 cb 09 d1 c3 01 fb 8d 5b ff 53 5f c1 c7 09 d1 cf 89 1e f8 83 d6 04 f8 83 d0 04 eb cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YF_2147717109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YF!bit"
        threat_id = "2147717109"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 58 69 c0 [0-4] 8b 4d dc c7 04 01 [0-4] 6a 04 58 69 c0 [0-4] 8b 4d dc c7 04 01 [0-4] 6a 04 58 69 c0 [0-4] 8b 4d dc c7 04 01}  //weight: 1, accuracy: Low
        $x_1_2 = {0b c0 74 02 ff e0 68 ?? ?? ?? ?? b8 ?? ?? ?? ?? ff d0 ff e0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 08 8b 00 ff 75 08 ff 50 08 8b 45 fc 8b 4d ec 64 89 0d 00 00 00 00 5f 5e 5b c9 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_CR_2147726560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.CR!bit"
        threat_id = "2147726560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 d2 c1 6d ?? 08 89 5d ?? 89 4d ?? c7 45 ?? 64 00 00 00 8a 4d ?? 02 4d ?? 02 4d ?? 02 c8 02 d1 ff 4d ?? 75 ee 30 97 ?? ?? ?? ?? 0f b6 ca 03 cf 03 c1 47 3b fe a3 ?? ?? ?? ?? 7c b4 6a 40 68 00 30 00 00 56 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 14 0f 88 11 41 4e 75 f7 8b 0d ?? ?? ?? ?? 8d 84 08 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_AAA_2147727017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.AAA!bit"
        threat_id = "2147727017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 8a 48 fc 88 4d f3 0f b6 55 f3 81 f2 ?? 00 00 00 52 8b 45 f8 50 68 34 c1 40 00 8b 4d f8 51 e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 02 6a 01 8b 95 ?? ff ff ff 52 ff 55 fc 89 85}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 00 6a 24 6a 00 6a 00 6a 00 ff 95 ?? ?? ff ff 50 6a 00 ff 95 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_B1_2147730077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.B1"
        threat_id = "2147730077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c0 89 45 fc 90 90 8b 75 fc 03 75 f8 80 36 01 90 90 ff 45 fc 81 7d fc ?? ?? 00 00 75 e7}  //weight: 2, accuracy: Low
        $x_1_2 = "Control\\Keyboard Layouts\\%.8x" ascii //weight: 1
        $x_1_3 = "vrThhVOMilu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Injector_A_2147740729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.A!MTB"
        threat_id = "2147740729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "StartRemoval" ascii //weight: 1
        $x_1_2 = {8d 49 00 8a 04 0a 34 ?? 88 01 83 c1 01 83 ef 01 75 f1 8d 4c 24 1c 51 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_B_2147740948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.B!MTB"
        threat_id = "2147740948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 39 ec 88 94 0d ?? ?? ff ff 41 83 f9 ?? 72 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {89 01 40 83 c1 04 3d 00 01 00 00 7c f3}  //weight: 1, accuracy: High
        $x_1_3 = {81 e7 ff 00 00 00 89 7c b4 14 8b 5c 8c 14 03 df 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43 8a 5c 9c 14 30 1c 2a 42 3b d0 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_DSK_2147744215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.DSK!MTB"
        threat_id = "2147744215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 e0 33 d2 b9 04 00 00 00 f7 f1 8b 45 e8 0f be 0c 10 8b 55 e0 0f b6 82 ?? ?? ?? ?? 33 c1 8b 4d e0 88 81 ?? ?? ?? ?? eb c4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_PA_2147744731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.PA!MTB"
        threat_id = "2147744731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {6a 00 ff d5 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 3b 81 fe 1e 10 00 00 75 ?? 8d 54 24 10 52 8d 44 24 18 50 6a 00 8d 4c 24 24 51 6a 00 6a 00 ff 15 ?? ?? ?? ?? 47 3b fe 7c 08 00 81 fe ?? ?? 00 00 75}  //weight: 20, accuracy: Low
        $x_1_2 = {69 c9 fd 43 03 00 56 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? 00 81 3d ?? ?? ?? ?? ?? ?? 00 00 8b 35 ?? ?? ?? ?? 75 06 00 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MR_2147750940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MR!MTB"
        threat_id = "2147750940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GqNRmavanyj8CLfXujh4OCKJQI523" wide //weight: 1
        $x_1_2 = "mL0PZYeR2JFKY237" wide //weight: 1
        $x_1_3 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MR_2147750940_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MR!MTB"
        threat_id = "2147750940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 02 17 8d ?? ?? ?? 01 25 16 1f ?? 9d 6f ?? ?? ?? 0a 0b 00 07 0c 16 0d 2b ?? 08 09 9a 13 ?? 00 06 11 ?? 1f ?? 28 ?? ?? ?? 0a d1 6f ?? ?? ?? 0a 26 00 09 17 58 0d 09 08 8e 69 32}  //weight: 1, accuracy: Low
        $x_1_2 = {06 0b 07 13 ?? 11 ?? 0d 09 2c ?? 09 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 2d ?? 2b ?? 2b ?? 07 28 ?? ?? ?? 06 74 ?? ?? ?? 01 0c 08 28 ?? ?? ?? 06 00 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MS_2147750941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MS!MTB"
        threat_id = "2147750941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NT0tOUZClO57Fx5V51EmGPLLrL249" wide //weight: 1
        $x_1_2 = "iw89qJS0N6wWAanBeC2IP131" wide //weight: 1
        $x_1_3 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_2147751258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MT!MTB"
        threat_id = "2147751258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 56 57 a1 ?? ?? ?? ?? 31 45 ?? 33 c5 50 89 65 ?? ff 75 ?? 8b 45 ?? c7 45 ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? 64 a3 00 00 00 00 c3}  //weight: 5, accuracy: Low
        $x_1_2 = "The QUICK brown fox jumps over the lazy dog" ascii //weight: 1
        $x_1_3 = "<=>?attach this file with e-mail" ascii //weight: 1
        $x_1_4 = "someone is looking: %s" ascii //weight: 1
        $x_1_5 = "i spent too much time on training" ascii //weight: 1
        $x_1_6 = "do not detect it as if spyware:" ascii //weight: 1
        $x_1_7 = "never trust anyone: %s" ascii //weight: 1
        $x_1_8 = "mever lose your faith:" ascii //weight: 1
        $x_1_9 = "something( %lf ) is happening over there %lf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Injector_MU_2147751655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MU!MTB"
        threat_id = "2147751655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 58 c1 [0-32] 66 0f 6e e6 [0-16] 66 0f 6e e9 [0-10] 0f 57 ec [0-16] 66 0f 7e e9 [0-21] 39 c1 [0-32] 0f 77 [0-16] 46 [0-16] 8b 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_C_2147754904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.C!MTB"
        threat_id = "2147754904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 39 db 85 c0 39 db ff 34 0f 85 c0 d9 d0 85 c0 31 34 24 85 c0 39 db 85 c0 8f 04 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_D_2147754958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.D!MTB"
        threat_id = "2147754958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inf\\usbstor.inf" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii //weight: 1
        $x_1_3 = "\\AntiOpenProcess.dll" ascii //weight: 1
        $x_1_4 = "hookdll.dll" ascii //weight: 1
        $x_1_5 = "InstallHook" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_KA_2147761975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.KA"
        threat_id = "2147761975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 47 20 48 8d 05 ?? ?? ?? ?? 48 89 47 28 48 8d 05 ?? ?? ?? ?? 48 89 47 30 48 8d 05 ?? ?? ?? ?? 48 89 47 38 48 8d 05 ?? ?? ?? ?? 48 89 47 40 48 8d 05 ?? ?? ?? ?? 48 89 47 48 8b 44}  //weight: 2, accuracy: Low
        $x_1_2 = "qq.com" ascii //weight: 1
        $x_1_3 = "FlushProcessWriteBuffers" ascii //weight: 1
        $x_1_4 = "C:\\TEMP\\Fluck_32.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MW_2147772402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MW!MTB"
        threat_id = "2147772402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 43 01 8b 07 89 43 05 89 1f 83 c3 0d 8b c3 2b c6 3d ?? ?? ?? ?? 7c 0d 00 c6 03 e8 8d 56 04 8b c3 [0-16] 83 c0 05 2b d0 8b c2 c3}  //weight: 1, accuracy: Low
        $x_1_2 = "Full-Source_ShareAppsCrack.com" ascii //weight: 1
        $x_1_3 = "C:\\Users\\HiddenTask\\Downloads" ascii //weight: 1
        $x_1_4 = "UXTHEME.DLL" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_6 = "MSH_WHEELSUPPORT_MSG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MY_2147774293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MY!MTB"
        threat_id = "2147774293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gxkeoxkzs" ascii //weight: 1
        $x_1_2 = "Project51.dll" ascii //weight: 1
        $x_1_3 = "StgGetIFillLockBytesOnFile" ascii //weight: 1
        $x_1_4 = "loadperf.dll" ascii //weight: 1
        $x_1_5 = "IUnknown_AddRef_Proxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MZ_2147774295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MZ!MTB"
        threat_id = "2147774295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gxkeoxkzs" ascii //weight: 1
        $x_1_2 = "Project51.dll" ascii //weight: 1
        $x_1_3 = "midiInStop" ascii //weight: 1
        $x_1_4 = "midiOutGetVolume" ascii //weight: 1
        $x_1_5 = "mixerGetID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MBK_2147781346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MBK!MTB"
        threat_id = "2147781346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 00 75 00 6e 00 6b 00 20 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 43 00 6f 00 6d 00 70 00 72 00 65 00 68 00 65 00 6e 00 73 00 [0-48] 5c 00 73 00 77 00 61 00 70 00 72 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = "CryptoPic" wide //weight: 1
        $x_1_3 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 [0-16] 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = {52 00 65 00 67 00 57 00 72 00 69 00 74 00 65 00 [0-16] 73 00 65 00 6c 00 66 00}  //weight: 1, accuracy: Low
        $x_1_6 = "Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.EXE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_EPMB_2147783317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.EPMB!MTB"
        threat_id = "2147783317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Cesarumenuvcer" ascii //weight: 1
        $x_1_2 = "ewrdsceswa" ascii //weight: 1
        $x_1_3 = "umerdxnscseqw" ascii //weight: 1
        $x_1_4 = "Nummdadkoawd" ascii //weight: 1
        $x_1_5 = "ec2ndm4seaw7dmc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ACL_2147787057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ACL!MTB"
        threat_id = "2147787057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 f9 02 78 ?? f3 a5 89 c1 83 e1 03 f3 a4 5f 5e}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8b 45 d4 03 45 e0 03 45 e8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 8b 45 ec 31 18 6a 00}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f0 03 45 d8 2d ?? ?? ?? ?? 83 c0 04 89 45 fc 89 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_EPQX_2147787059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.EPQX!MTB"
        threat_id = "2147787059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 04 83 c6 00 83}  //weight: 1, accuracy: High
        $x_1_2 = {d2 d2 d2 d2 83 ea 00 81 34 2f ?? ?? ?? ?? 83 e8 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_EPQX_2147787059_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.EPQX!MTB"
        threat_id = "2147787059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 34 0b 5a 81 f2 ?? ?? ?? ?? 09 14 0f 83 c1 fc}  //weight: 1, accuracy: Low
        $x_1_2 = "Utilgivelighedernes1" ascii //weight: 1
        $x_1_3 = "Sammentrykkes2" ascii //weight: 1
        $x_1_4 = "Temporisers4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MA_2147787625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MA!MTB"
        threat_id = "2147787625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c7 44 24 8c 2a 00 00 00 83 ff 03 48}  //weight: 3, accuracy: High
        $x_3_2 = {83 fe 3f c7 84 24 7c ff ff ff f6 00 00 00 83 f9 40 89 3e}  //weight: 3, accuracy: High
        $x_4_3 = {c7 44 24 8c b3 00 00 00 81 fa aa 00 00 00 81 ff cd 00 00 00 81 f9 d2 00 00 00}  //weight: 4, accuracy: High
        $x_2_4 = {89 3e c7 84 24 7c ff ff ff 00 00 00 00 83 fa 0a 83 f9 3f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Injector_MA_2147787625_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MA!MTB"
        threat_id = "2147787625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d f8 83 c1 01 89 4d f8 8b 55 f8 3b 55 e8 0f 83 ?? ?? ?? ?? 8b 45 f4 03 45 f8 8a 08 88 4d ff}  //weight: 2, accuracy: Low
        $x_1_2 = "Loader.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MA_2147787625_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MA!MTB"
        threat_id = "2147787625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ujmakfun.dll" ascii //weight: 1
        $x_1_2 = "hryabw" ascii //weight: 1
        $x_1_3 = "inehp" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "CreateFile" ascii //weight: 1
        $x_1_6 = "WNetAddConnection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ZA_2147787628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ZA!MTB"
        threat_id = "2147787628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 c9 83 c2 04 84 c9 83 c7 04}  //weight: 1, accuracy: High
        $x_1_2 = {66 85 db 31 f5 84 c0 31 2c 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_DD_2147788162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.DD!MTB"
        threat_id = "2147788162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {87 5c 7f 17 f7 e6 87 35 7f 2a f7 01 87 24 7f 40 f7 a8 87 86 7f 59 f7 78 87 19 7f 37 f7 8d 87 69 7f af f7 a0 87 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_DE_2147788163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.DE!MTB"
        threat_id = "2147788163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 71 07 30 60 87 5f 20 ae 8b 03 6e 47 a5 22 24 0b 16 6c 44 80 ac 5b 3a fd 9d b6 2c 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_GI_2147788250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.GI!MTB"
        threat_id = "2147788250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 00 00 00 00 81 c2 01 00 00 00 bf 21 29 6d dd 09 ff 31 18 01 ff 01 d2 81 c0 02 00 00 00 21 d7 09 d7 ba 46 b4 0d 90 39 c8}  //weight: 1, accuracy: High
        $x_1_2 = {be 00 00 00 00 01 c3 81 c3 7d ab 0f 17 b8 86 3b c0 52 01 c0 81 e8 2a 4c f3 36 31 17 48 09 db 48 81 c7 02 00 00 00 f7 d3 29 d8 39 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Injector_ZC_2147788254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ZC!MTB"
        threat_id = "2147788254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 33 81 ea ?? ?? ?? ?? 01 d2 81 c0 01 00 00 00 43 29 c2 ba ?? ?? ?? ?? 09 d2 39 cb 75 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RAQ_2147794197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RAQ!MTB"
        threat_id = "2147794197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 01 00 00 75 05 [0-32] c3 80 00 [0-32] e8 ?? 00 00 00 [0-32] 31 [0-32] 39 ?? (7c|75) [0-32] c3 [0-32] 8d [0-32] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MRTY_2147794543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MRTY!MTB"
        threat_id = "2147794543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f946338be1333933d1193f3339696" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MRVF_2147794613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MRVF!MTB"
        threat_id = "2147794613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 33 71 b5 e2 d6 34 d1 ed}  //weight: 1, accuracy: High
        $x_1_2 = {b7 04 00 ff 04 28 ff 05 01 00 24 02 00 0d 14 00 03 00 08 28 ff 0d 50 00 04 00 6c 00 ff 5e 18 00 04 00 71 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_YTRE_2147794614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.YTRE!MTB"
        threat_id = "2147794614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pMM:DocumentID>adobe:docid:photoshop:e4a3f931-627e-11dc-ba81-9bfb3cc4cbdf</xapMM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_STRR_2147794617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.STRR!MTB"
        threat_id = "2147794617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "t.ptlogin2.qq.com:4300/pt_get_uins?callback=ptui_getuins_CB&r=0.7478418888058513&pt_local_tk=0.38584163924" ascii //weight: 1
        $x_1_2 = "Http DownLoad" ascii //weight: 1
        $x_1_3 = "HK_VirtualProtectEx" ascii //weight: 1
        $x_1_4 = "HK_WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "TrikIE/1.0" ascii //weight: 1
        $x_1_6 = "XDriverGetStatus OpenService()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_LPP_2147794618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.LPP!MTB"
        threat_id = "2147794618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 bc b6 9c 33 bc b6 9c 33 bc b6 9c 5c a3 bc 9c 37 bc b6 9c 5c a3 b2 9c 31 bc b6 9c 33 bc b7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_CVBN_2147794620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.CVBN!MTB"
        threat_id = "2147794620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c8 bf 04 00 00 00 99 f7 ff 8b 7d e0 8a 04 17 30 04 0b 41 39 f1 7c e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_CVBN_2147794620_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.CVBN!MTB"
        threat_id = "2147794620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b 84 55 04 ff ff ff 33 c8 8b 95 f8 fe ff ff 81 e2 ff ff 00 00 33 ca f7 d1 8b 85 f8 fe ff ff 25 ff ff 00 00 8b 55 08 88 0c 02 66 8b 85 fc fe ff ff 66 05 01 00 66 89 85 fc fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPA_2147795761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPA!MTB"
        threat_id = "2147795761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f8 00 00 00 00 c7 45 f8 00 00 00 00 eb 09 8b 4d f8 83 c1 01 89 4d f8 81 7d f8 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 8b 55 f8 8a 82}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7d 0c 00 74 1a 8b 4d fc c6 01 00 8b 55 fc 83 c2 01 89 55 fc 8b 45 0c 83 e8 01 89 45 0c eb e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MPYY_2147795819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MPYY!MTB"
        threat_id = "2147795819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 35 35 33 19 e9 e7 09 bd f0 54 4d 97 c4 03 7c ee}  //weight: 1, accuracy: High
        $x_1_2 = {32 f0 23 2e 1c 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPW_2147796515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPW!MTB"
        threat_id = "2147796515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d c4 00 00 00 83 fb 1a 31 db 83 f8 00 83 fa 0d 33 1c 0e 83 fa 57 83 fb 5d 09 1c 08 81 fb a3 00 00 00 81 f9 fa 00 00 00 31 3c 08 83 f8 11 81 fb 9b 00 00 00 81 e9 42 02 00 00 83 f9 21 83 f9 1b 81 c1 3d 02 00 00 90 83 f9 1a 41 7d b3 83 f8 02 81 fa d5 00 00 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPW_2147796515_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPW!MTB"
        threat_id = "2147796515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tecnologgando" ascii //weight: 1
        $x_1_2 = "Betty" ascii //weight: 1
        $x_1_3 = "Trumpa" ascii //weight: 1
        $x_1_4 = "kernel32" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "DeCritta" ascii //weight: 1
        $x_1_7 = "Stampa" ascii //weight: 1
        $x_1_8 = "Installami" ascii //weight: 1
        $x_1_9 = {40 00 ff d0 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPW_2147796515_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPW!MTB"
        threat_id = "2147796515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 02 00 00 00 [0-16] 39 ca 7e 30 00 [0-32] 8a 1a [0-16] 88 1e [0-16] 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_KRT_2147797362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.KRT!MTB"
        threat_id = "2147797362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 05 b8 0b d8 09 bf 04 ef 01 12 25 00 ff 03 1b 00 00 00 05 05 00 4c 69 73 74 33 00 08 04 b8 0b d8 09 bf 04 c2 01 11 24 00 ff 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_IOP_2147797363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.IOP!MTB"
        threat_id = "2147797363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 09 21 12 1d 38 39 17 2d 1c 0c 19 09 38 1e 09 30 02 0c 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MRVU_2147797366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MRVU!MTB"
        threat_id = "2147797366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 4c 64 24 5f e6 e5 a0 c3 e7 94 92 32 8c 56 da 50 d8 e9}  //weight: 1, accuracy: High
        $x_1_2 = {43 d3 77 aa 4c 81 b3 5b 75 3e a1 17 e7 fa 9a de 7d bb 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MPY_2147797779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MPY!MTB"
        threat_id = "2147797779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 31 00 00 00 00 66 61 31 00 0c 00}  //weight: 1, accuracy: High
        $x_1_2 = {33 71 b5 86 8e bf c7 50 7e 90 41 8e 94 26 00 83 0f 56 59 2a 3d fb fc fa a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPX_2147797924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPX!MTB"
        threat_id = "2147797924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 db 83 fa 29 83 f9 43 33 1c 0e 83 fb 50 83 fa 76 09 1c 08 83 f8 6d 81 fa aa 00 00 00 31 3c 08 83 fb 4d 81 f9 91 00 00 00 81 e9 42 02 00 00 83 f8 36 81 f9 97 00 00 00 81 c1 3d 02 00 00 3d f1 00 00 00 81 fa 8a 00 00 00 41 7d b2 81 f9 bf 00 00 00 81 fa db 00 00 00 ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RTG_2147798659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RTG!MTB"
        threat_id = "2147798659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff 83 c0 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_INK_2147798664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.INK!MTB"
        threat_id = "2147798664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 0c 00 00 00 32 37 34 39 41 38 45 43 42 34 30 32 00 00 00 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPD_2147805655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPD!MTB"
        threat_id = "2147805655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 fa 05 0f b6 05}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e0 03 0b d0 88 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_DFE_2147806252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.DFE!MTB"
        threat_id = "2147806252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 3b 87 aa 7f 2c f7 0f 87 4c 7f 17 f7 79 87 e3 7f 96 f7 86 87 98 7f de f7 91 87 6c 7f e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_JNK_2147807576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.JNK!MTB"
        threat_id = "2147807576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 00 08 04 40 0b 98 0d bf 04 c2 01 11 0a 00 ff 03 26 00 00 00 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_JNK_2147807576_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.JNK!MTB"
        threat_id = "2147807576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 8b 10 66 3b 11 0f 85 1b 03 00 00 66 3b d3 74 19 66 8b 50 02 66 3b 51 02 0f 85 08 03 00 00 83 c0 04 83 c1 04 66 3b d3 75 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPQ_2147807727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPQ!MTB"
        threat_id = "2147807727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 50 46 30 06 54 46 6f 72 6d 33 05 46 6f 72 6d 33 04 4c 65 66 74 03 c0 00 03 54 6f 70 02 7c 05 57 69 64 74 68 03 88 04 06 48 65 69 67 68 74 03 58 02 07 43 61 70 74 69 6f 6e 06 05 46 6f 72 6d 33 05 43 6f 6c 6f 72 07 09 63 6c 42 74 6e 46 61 63 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPV_2147807730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPV!MTB"
        threat_id = "2147807730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 50 46 30 06 54 46 6f 72 6d 32 05 46 6f 72 6d 32 04 4c 65 66 74 03 ee 00 03 54 6f 70 03 a8 00 05 57 69 64 74 68 03 f8 02 06 48 65 69 67 68 74 03 cf 01 07 43 61 70 74 69 6f 6e 06 05 46 6f 72 6d 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPG_2147807855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPG!MTB"
        threat_id = "2147807855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 18 81 c2 9f bd 7a b1 40 81 ee 01 00 00 00 81 ee 44 84 a8 a5 39 c8 75 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPH_2147807856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPH!MTB"
        threat_id = "2147807856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 24 00 00 00 31 13 [0-16] 81 c3 01 00 00 00 [0-16] 39 c3 75 da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPI_2147807857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPI!MTB"
        threat_id = "2147807857"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 3e 29 c1 48 81 c6 04 00 00 00 [0-16] 39 de 75 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPJ_2147807858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPJ!MTB"
        threat_id = "2147807858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 db 31 0a [0-16] 81 c2 01 00 00 00 39 fa 75 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPK_2147807859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPK!MTB"
        threat_id = "2147807859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 c9 74 01 ea 31 32 [0-16] 81 c2 04 00 00 00 [0-16] 39 ca 75 e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPL_2147807860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPL!MTB"
        threat_id = "2147807860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 db 74 01 ea 31 10 [0-16] 81 c0 04 00 00 00 [0-16] 39 f8 75 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_RPM_2147807861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.RPM!MTB"
        threat_id = "2147807861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 01 ea 31 1e [0-16] 81 c6 04 00 00 00 [0-32] 39 fe 75 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_TH_2147808812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.TH!MTB"
        threat_id = "2147808812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 5c 31 06 32 1c 11 80 e3 df 75 ed 49 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = {2b c3 8b c8 33 11 f7 c2 fe ff ff ff 74 0a}  //weight: 1, accuracy: High
        $x_1_3 = "Debugger   detected!   Doggone   it   all!" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ARA_2147834298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ARA!MTB"
        threat_id = "2147834298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 99 f7 7d 10 8b 45 0c 47 3b fe 8a 04 02 88 84 3d ff fe ff ff 7c e8}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 0c 8a 19 0f b6 14 08 0f b6 c3 03 fa 03 c7 8b fe 99 f7 ff 8b 45 08 8b fa 8a 14 38 03 c7 88 11 41 ff 4d 10 88 18 75 d7 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ARA_2147834298_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ARA!MTB"
        threat_id = "2147834298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\Public\\Documents\\zy.log" ascii //weight: 2
        $x_2_2 = "software\\WOW6432Node\\Tencent\\QQ2009\\Install" ascii //weight: 2
        $x_2_3 = "HipsTray.exe" ascii //weight: 2
        $x_2_4 = "360tray.exe" ascii //weight: 2
        $x_2_5 = "V@\\bhdll.dat" ascii //weight: 2
        $x_2_6 = "fuckyou2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_SE_2147888538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.SE!MTB"
        threat_id = "2147888538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 02 8b 45 ?? 03 45 ?? 89 45 ?? 6a ?? e8 ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 2b d0 8b 45 ?? 31 10 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b d8 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ABI_2147899448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ABI!MTB"
        threat_id = "2147899448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b c1 66 87 d2 66 0b d2 80 ee c0 2b f1 8b 4d c8 66 0f a3 da 66 8b d1 f8 66 c1 ea 05 66 2b ca 66 0f bc d1 f6 da 66 0f c1 d2 8b 55 f4 85 ca 81 fd e9 47}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_NIT_2147927359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.NIT!MTB"
        threat_id = "2147927359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {53 bb 6c d6 41 00 68 34 5e 40 00 e8 e0 ff ff ff 89 03 68 44 5e 40 00 8b 03 50 e8 d9 ff ff ff a3 b0 d6 41 00 68 54 5e 40 00 8b 03 50 e8 c7 ff ff ff a3 ac d6 41 00 68 68 5e 40 00 8b 03 50 e8 b5 ff ff ff a3 b4 d6 41 00 68 7c 5e 40 00 8b 03 50 e8 a3 ff ff ff a3 d0 d6 41 00 68 88 5e 40 00 8b 03 50 e8 91 ff ff ff a3 d8 d6 41 00 68 9c 5e 40 00 8b 03 50 e8 7f ff ff ff a3 e8 d6 41 00 68 b8 5e 40 00 8b 03 50 e8 6d ff ff ff a3 ec d6 41 00 68 c8 5e 40 00 8b 03 50 e8 5b ff ff ff a3 f0 d6 41 00 68 d8 5e 40 00 8b 03 50 e8 49 ff ff ff a3 f4 d6 41 00 68 e8 5e 40 00 8b 03}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_BA_2147931029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.BA!MTB"
        threat_id = "2147931029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b f9 57 31 1f 83 c7 04 ?? ?? ?? ?? ?? 8b 3c 24 4d c0 e9 55 8b 3c 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_EAXW_2147932234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.EAXW!MTB"
        threat_id = "2147932234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 14 06 8b d8 32 d1 d1 eb 83 c0 02 88 94 1c 20 02 00 00 3d 70 17 00 00 72 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_EAVX_2147935742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.EAVX!MTB"
        threat_id = "2147935742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 4e fb 33 c0 8d 49 00 8a 14 06 8b d8 32 d1 d1 eb 83 c0 02 88 94 1c 20 02 00 00 3d 70 17 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_PAQD_2147939603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.PAQD!MTB"
        threat_id = "2147939603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 fc 8b 32 33 c0 85 f6 7e ?? 8b 55 08 8a 14 10 30 14 07 40 3b c6 7c ?? 83 45 fc 04 83 c7 19 81 7d fc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_LMA_2147949012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.LMA!MTB"
        threat_id = "2147949012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 45 fc 6b c0 33 8b 55 ?? d1 fa 09 c2 8b 45 ?? 31 d0 89 45 ?? 8b 45 ?? 83 e0 0f 83 f8 0a 0f 94 c0 84 c0}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 45 fc 83 e0 01 85 c0 75 ?? 8b 45 f8 33 45 fc 89 45 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_KAB_2147951030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.KAB!MTB"
        threat_id = "2147951030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {03 7d b8 81 ef ?? ?? ?? ?? 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d e0 72}  //weight: 20, accuracy: Low
        $x_10_2 = {8b d6 03 55 c8 03 c2 8b 55 e8 03 d7 8b 4d d4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_KAC_2147951399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.KAC!MTB"
        threat_id = "2147951399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {83 5e 46 14 f6 6a 6e f6 5f 12 a4 44 82 99 cf 58 39 9e e0 67 3a 4f ad 33 99 66 cf 11 b7 0c}  //weight: 10, accuracy: High
        $x_5_2 = "Earthworms1" ascii //weight: 5
        $x_3_3 = "Hearingless" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_SX_2147953719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.SX!MTB"
        threat_id = "2147953719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 84 83 c2 ?? 89 55 84 83 7d 84 01 7d ?? c7 45 a0 ?? ?? ?? ?? 8b 45 a0 0b 45 a0 0f af 45 a0 0f af 45 a0 89 45 a0 eb}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 08 2b ca 8b 55 bc 2b d1 89 55 bc 8b 45 c4 83 e0 ?? 0f af 45 bc 0f af 45 bc 89 45 bc}  //weight: 2, accuracy: Low
        $x_1_3 = "SCardDisconnect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_ARR_2147954233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.ARR!MTB"
        threat_id = "2147954233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_30_1 = {8b 4d f4 83 c1 01 8b 55 fc 8b 02 99 f7 f9 0f af 45 f4 89 45 f4 c7 85 48}  //weight: 30, accuracy: High
        $x_20_2 = {8b 45 fc 0b 45 f8 8b 4d f8 23 4d f8 0f af c1 0f af 45 f8 89 45 f8 eb}  //weight: 20, accuracy: High
        $x_30_3 = {8b 85 3c ff ff ff 8b 0c 90 33 0d c4 a1 43 00 8b 95 60 ff ff ff 8b 85 3c ff ff ff}  //weight: 30, accuracy: High
        $x_20_4 = {8b 4d fc 83 c1 01 8b 45 fc 99 f7 f9 0f af 45 fc 89 45 fc 8d 55 fc}  //weight: 20, accuracy: High
        $x_30_5 = {8d 45 dc 89 45 b4 8b 4d b4 8b 55 ac 0f af 11 0f af 55 a8 89 55 a8 c7 45 e4}  //weight: 30, accuracy: High
        $x_20_6 = {8b 4d 08 83 c1 01 8b 45 fc 99 f7 f9 0f af 45 10 89 45 10}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*))) or
            ((1 of ($x_30_*) and 1 of ($x_20_*))) or
            ((2 of ($x_30_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Injector_MK_2147956188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MK!MTB"
        threat_id = "2147956188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {c6 85 d8 f5 ff ff 36 c6 85 d9 f5 ff ff 36 c6 85 da f5 ff ff 36 88 95 db f5 ff ff}  //weight: 15, accuracy: High
        $x_10_2 = {c6 85 f2 f5 ff ff 33 c6 85 f3 f5 ff ff 35 c6 85 f4 f5 ff ff 6d c6 85 f5 f5 ff ff 57 c6 85 f6 f5 ff ff 68}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_KK_2147957799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.KK!MTB"
        threat_id = "2147957799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {be 72 31 e3 ee 09 f6 e8 ?? ?? ?? ?? bf 1b c8 85 31 31 11 bf 45 b7 b6 28 01 f7 21 ff 81 c1 02 00 00 00 81 ef e8 53 06 59 4e 21 ff 39 c1}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injector_MKA_2147958985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injector.MKA!MTB"
        threat_id = "2147958985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {24 c1 bc 00 ee c0 bc 00 6c 69 62 63 75 72 6c 2e}  //weight: 15, accuracy: High
        $x_10_2 = {40 a6 25 00 d0 08 01 00 80 36 06 00 ac 68 24}  //weight: 10, accuracy: High
        $x_5_3 = {ac 68 24 00 34 c0 bc 00 41 c0 bc 00 50 c0 bc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

