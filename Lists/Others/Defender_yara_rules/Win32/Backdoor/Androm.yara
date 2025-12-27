rule Backdoor_Win32_Androm_MK_2147776153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.MK!MTB"
        threat_id = "2147776153"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {e9 00 00 00 5c 14 40 00 5c 14 40 00 18 14 40 00 78}  //weight: 15, accuracy: High
        $x_10_2 = {94 26 85 00 24 15 40 00 7c 1e 40 00 a0 1e 40}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_MK_2147776153_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.MK!MTB"
        threat_id = "2147776153"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JumpID(\"\",\"%s\")" ascii //weight: 1
        $x_1_2 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" ascii //weight: 1
        $x_1_3 = "AllowChange" ascii //weight: 1
        $x_1_4 = "SaveClipboard" ascii //weight: 1
        $x_1_5 = "http://stas258.narod.ru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_CB_2147814339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.CB!MTB"
        threat_id = "2147814339"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4f 11 f6 30 ca 50 08 60 ?? 61 75 e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_DA_2147817690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.DA!MTB"
        threat_id = "2147817690"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 45 08 8b 4d 0c 0f b6 11 33 c2 88 45 08 8b 45 0c 83 c0 01 89 45 0c 8b 4d 10 83 e9 01 89 4d 10 eb d7}  //weight: 2, accuracy: High
        $x_2_2 = "VirtualAlloc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_BG_2147825045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.BG!MTB"
        threat_id = "2147825045"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ff 8b 0d [0-4] 8a 94 31 [0-4] a1 [0-4] 88 14 30 81 3d [0-4] ab 05 00 00 75}  //weight: 2, accuracy: Low
        $x_1_2 = {3d cb d9 0b 00 75 06 81 c1 [0-4] 40 3d 3d a6 15 00 7c}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fe 2b ac 01 00 7e 08 81 fb e1 be f5 00 75 09 46 81 fe b6 2d bc 1e 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_BT_2147830626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.BT!MTB"
        threat_id = "2147830626"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "geplux.tk/lsas.exe" wide //weight: 1
        $x_1_2 = "0794857ffe244509b65b805e5e29ac2c5ea33d3f_v1.4" wide //weight: 1
        $x_1_3 = "TASKKILL /im br.exe /f" ascii //weight: 1
        $x_1_4 = "bot%s/getMe" wide //weight: 1
        $x_1_5 = "START br.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_MA_2147833616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.MA!MTB"
        threat_id = "2147833616"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {51 51 53 55 56 57 8b f9 33 c9 8b 47 3c 8b 44 38 78 03 c7 8b 50 20 8b 58 1c 03 d7 8b 68 24 03 df 8b 40 18 03 ef 89 54 24 14 89 44 24 10 85 c0 74}  //weight: 5, accuracy: High
        $x_1_2 = "wallet.dat" ascii //weight: 1
        $x_1_3 = "\\Exodus\\exodus.wallet\\" ascii //weight: 1
        $x_1_4 = "\\Yandex\\YandexBrowser\\" ascii //weight: 1
        $x_1_5 = "CookiesOpera" ascii //weight: 1
        $x_1_6 = "Screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_BC_2147835235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.BC!MTB"
        threat_id = "2147835235"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 8b c6 f7 75 08 8a 0c 1a 30 0c 3e 46 3b 75 10 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_AM_2147837980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.AM!MTB"
        threat_id = "2147837980"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {86 d3 96 22 62 a9 ba 3b 27 38 36 30 13 13 99 1c 04 03 20 26 26 80 80 52 d5 f9 32 44 44 7a}  //weight: 1, accuracy: High
        $x_1_2 = {27 19 21 30 13 86 ee ba ba bb 26 09 5a 21 26 ad 31 44 44 7a 04 eb 6a e3 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GCS_2147838513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GCS!MTB"
        threat_id = "2147838513"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f4 83 c0 01 89 45 f4 81 7d f4 ff 00 00 00 7d 0b 8b 4d f0 33 4d f4 89 4d f0 eb ?? 8b 55 f0 33 55 ec 83 f2 0f 8b 45 08 03 45 fc 88 10}  //weight: 10, accuracy: Low
        $x_1_2 = "3CreateMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_AO_2147840140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.AO!MTB"
        threat_id = "2147840140"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {95 12 00 fc 95 12 00 10 96 12 00 20 96 12 00 32 96 12 00 46 96 12 00 5a 96 12 00 66 96 12 00 76}  //weight: 2, accuracy: High
        $x_2_2 = "c:\\parche\\tictac.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GHN_2147845125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GHN!MTB"
        threat_id = "2147845125"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 57 8b 7d 10 33 f6 85 ff 74 0f 0f b6 0c 06 8a 0c 11 88 0c 06 46 3b f7 72 f1 5f 5e 5d c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GJO_2147848499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GJO!MTB"
        threat_id = "2147848499"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec 20 b8 ?? ?? ?? ?? 81 75 ?? ff 00 ff 00 83 f8 07 ?? ?? 29 d2 83 6d fc 77 66 ba 61 00 3b 55 f8 ?? ?? c7 45 ?? 40 00 00 00 b9 ?? ?? ?? ?? 83 6d f4 04 83 f9 00 ?? ?? 8b 45 ec 8d 45 f4 81 f8 aa 09 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "max Edition.exe" ascii //weight: 1
        $x_1_3 = ".ropf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_BP_2147849507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.BP!MTB"
        threat_id = "2147849507"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Affaldsskakten\\pressefold\\duelbene" ascii //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Bochur\\Maliceproof\\Desulfurisation\\automatizations" ascii //weight: 2
        $x_1_3 = "[Rename]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GKZ_2147850148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GKZ!MTB"
        threat_id = "2147850148"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 11 33 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 68 ?? ?? ?? ?? 6a 17 e8 ?? ?? ?? ?? 83 c4 08 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 0f be 11 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10}  //weight: 10, accuracy: Low
        $x_1_2 = "Moreg" ascii //weight: 1
        $x_1_3 = "Zapaz" ascii //weight: 1
        $x_1_4 = "@.ropf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GNT_2147852223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GNT!MTB"
        threat_id = "2147852223"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 04 39 8a 04 10 88 04 39 41 81 f9 60 26 00 00 72 ?? 8b 15 ?? ?? ?? ?? 8b cb 0f b6 04 31 8a 04 10 88 04 31 41 81 f9 00 b4 05 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_BQ_2147889100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.BQ!MTB"
        threat_id = "2147889100"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 45 ff 0f b6 75 ff 8a 14 06 00 55 fe 0f b6 4d fe 8a 1c 01 88 1c 06 88 14 01 0f b6 0c 06 0f b6 d2 03 ca 8b 55 f4 81 e1 ff 00 00 00 8a 0c 01 32 0c 3a 88 0f 47 ff 4d f8 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GMA_2147900265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GMA!MTB"
        threat_id = "2147900265"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 8b f8 66 c7 44 24 18 02 00 ff 15 ?? ?? ?? ?? 66 89 44 24 ?? 8b 47 0c 6a 10 8b 08 8d 44 24 ?? 50 8b 11 8b 4e 08 51 89 54 24 ?? ff 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GMB_2147900276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GMB!MTB"
        threat_id = "2147900276"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 14 57 6a 06 6a 01 8b f9 6a 02 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {8b f0 66 c7 44 24 ?? 02 00 ff 15 ?? ?? ?? ?? 66 89 44 24 16 8b 46 0c 68 ?? ?? ?? ?? 8b 08 8b 44 24 14 50 8b 11 89 54 24 20 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GMX_2147900759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GMX!MTB"
        threat_id = "2147900759"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f0 8b 44 24 ?? 50 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 8b f8 51 66 c7 44 24 ?? 02 00 ff d6 66 89 44 24 ?? 8b 57 ?? 68 ?? ?? ?? ?? 53 8b 02 8b 08 89 4c 24 ?? ff d5 8b 74 24 ?? 8d 54 24 ?? 6a 10 52 8b 4e ?? 51 ff d0 83 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GMY_2147901114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GMY!MTB"
        threat_id = "2147901114"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 24 8b d8 52 ff 15 ?? ?? ?? ?? 8b e8 8b 44 24 28 50 66 c7 44 24 ?? 02 00 ff d3 66 89 44 24 12 8b 4d 0c 68 ?? ?? ?? ?? 8b 11 8b 0d ?? ?? ?? ?? 51 8b 02 89 44 24 1c ff d6 8b 4f 08 8d 54 24 10 6a 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GXA_2147902932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GXA!MTB"
        threat_id = "2147902932"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 8b 5c 24 ?? 55 8b 6c 24 20 56 55 ff 15 ?? ?? ?? ?? 53 8b f0 66 c7 44 24 ?? 02 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {8b fb 6a 40 68 78 da 04 00 f3 a5 53 ff 15}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GXB_2147902940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GXB!MTB"
        threat_id = "2147902940"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f0 8b 44 24 24 50 ff 15 ?? ?? ?? ?? 8b 4c 24 28 8b f8 51 66 c7 44 24 14 02 00 ff d6 66 89 44 24 12 8b 57 0c 68 ?? ?? ?? ?? 53 8b 02 8b 08 89 4c 24 1c ff 15 ?? ?? ?? ?? 8b 4d 08 8d 54 24 10 6a 10 52 51 ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_GXZ_2147903165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.GXZ!MTB"
        threat_id = "2147903165"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 6a 40 68 78 da 04 00 53 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {8b ca 83 e1 03 f3 a4 8b 7b 04 8b ?? ?? ?? ?? ?? 03 fd 89 7b 04 ff d6 6a 0a ff d6 6a 0a ff d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Androm_CCHT_2147903238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Androm.CCHT!MTB"
        threat_id = "2147903238"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 9b 00 00 00 be ?? ?? ?? ?? f3 a5 8b 35 28 30 40 00 c7 83 8c da 04 00 01 00 00 00 ff d6 6a 0a ff d6 6a 0a ff d6 6a 0a ff d6 6a 0a ff d6 8b cb e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

