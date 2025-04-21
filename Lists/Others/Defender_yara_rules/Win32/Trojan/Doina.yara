rule Trojan_Win32_Doina_R_2147831286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.R!MTB"
        threat_id = "2147831286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 32 02 aa 42 49}  //weight: 1, accuracy: Low
        $x_1_2 = {ac 30 d0 aa c1 ca 08 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9 75 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_S_2147831787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.S!MTB"
        threat_id = "2147831787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ac 50 58 32 02 aa 42 49 85 c9 75 ed [0-53] ac 30 d0 aa c1 ca 08 49 85 c9 75 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_RPL_2147836945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.RPL!MTB"
        threat_id = "2147836945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS\\UCKH" wide //weight: 1
        $x_1_2 = "emaNlluFtpircS.tpircsW eliFeteleD.M" wide //weight: 1
        $x_1_3 = "reggubeDmetsyS" wide //weight: 1
        $x_1_4 = "s   y    s    D      e    b   u    g   .   v   b  s" wide //weight: 1
        $x_1_5 = "Wscript.Sleep 5000" wide //weight: 1
        $x_1_6 = "Bi t D ef e n d er" wide //weight: 1
        $x_1_7 = "Ka s p e r S k y" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_BD_2147837163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.BD!MTB"
        threat_id = "2147837163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {85 a1 a4 76 f2 fd ef 4f ae 07 50 d3 13 d2 08 69 fe 78 92 ae c7 51 e5 4a b5 3d 5f 96 3f 88 24 eb 19 c1 3e c5 2f 74 7e 4d a7 76}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_MA_2147844441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.MA!MTB"
        threat_id = "2147844441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 8b 4d 10 8a 09 88 08 8b 45 f8 40 89 45 f8 8b 45 10 40 89 45 10 8b 45 0c 48 89 45 0c eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GHJ_2147848006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GHJ!MTB"
        threat_id = "2147848006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 cc 83 c0 01 89 45 cc 8b 4d cc 3b 4d d0 7d ?? 8b 55 cc 52 8d 4d d4 e8 ?? ?? ?? ?? 0f be 18 83 f3 ?? 8b 45 cc 50 8d 4d d4 e8 ?? ?? ?? ?? 88 18}  //weight: 10, accuracy: Low
        $x_1_2 = "api.jwhss.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_EC_2147850524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.EC!MTB"
        threat_id = "2147850524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PTWjig56zOCj" ascii //weight: 1
        $x_1_2 = "JqyH0wvPCGw0" ascii //weight: 1
        $x_1_3 = "CKjCfmJTG" ascii //weight: 1
        $x_1_4 = "SystemMonitorCtl.SystemMonitor" ascii //weight: 1
        $x_1_5 = "SimSim.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GNX_2147852637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GNX!MTB"
        threat_id = "2147852637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 f3 f6 d9 28 e1 03 75 00 66 0f b6 ca 8a 46 ff a8 3f 66 81 f1 b7 4b 66 0f be cb}  //weight: 10, accuracy: High
        $x_10_2 = {30 d8 66 0f be d0 fe ca 0f 94 c6 88 14 24 fe c8}  //weight: 10, accuracy: High
        $x_1_3 = "P.vmp0" ascii //weight: 1
        $x_1_4 = "nbbfmEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_DW_2147852926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.DW!MTB"
        threat_id = "2147852926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 f6 5d 52 81 c9 6e 00 46 f7 89 f9 38 de 66 d3 ee 29 d9 66 0f be f2 f9 89 e6 f9 83 ef 04 66 0f a3 ce f9 f8 ff 37 e8 ?? ?? ?? ?? 84 f1 f9 39 df e9}  //weight: 1, accuracy: Low
        $x_1_2 = {bd f2 55 b7 f2 10 16 5f ed 33 19 bb 19 34 32 7f}  //weight: 1, accuracy: High
        $x_1_3 = {91 1b 0a 88 d2 19 e2 b4 9d fa fc d7 2e f8 30 66 2e b2 19 14 2e f8 30 76 95 7e}  //weight: 1, accuracy: High
        $x_1_4 = {bf d3 ec 94 1e e6 aa 34 75 f5 01 e7 5a 8b cc 28 7a 72 c3 e0}  //weight: 1, accuracy: High
        $x_1_5 = "P.vmp0" ascii //weight: 1
        $x_1_6 = "ckmS[q&wL" ascii //weight: 1
        $x_1_7 = "WVKOH!n" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_Doina_GME_2147888290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GME!MTB"
        threat_id = "2147888290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 56 18 8a 44 82 ff f7 ff 8a fc 8d 14 8a 3c 80 73 ?? 02 c0 eb ?? 34 1b 41 88 02 3b 0e}  //weight: 10, accuracy: Low
        $x_10_2 = {57 8b f8 b8 ?? ?? ?? ?? 48 46 08 9a c7 06 0a bf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GME_2147888290_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GME!MTB"
        threat_id = "2147888290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 f8 07 03 d0 5f 8b c2 5b 5d c3 8b c1 c1 e8 04 0f b7 1c 45 b0 c7 18 10 8d 3c 45 b2 c7 18 10 f6 c3 10 74 43 f6 c1 02 74 3e 8b c3 83 e0 0f 56 0f}  //weight: 10, accuracy: High
        $x_1_2 = "GA2RZNbm" ascii //weight: 1
        $x_1_3 = "t4SVh0b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_EM_2147888611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.EM!MTB"
        threat_id = "2147888611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svohost.bat" ascii //weight: 1
        $x_1_2 = "cmd /c net start rasauto" ascii //weight: 1
        $x_1_3 = "svehost.exe" ascii //weight: 1
        $x_1_4 = "linker.bin" ascii //weight: 1
        $x_1_5 = "cmd /c xcopy /s /i /h /e /q /y /d" ascii //weight: 1
        $x_1_6 = "cmd /c ipconfig /all" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GMG_2147888776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GMG!MTB"
        threat_id = "2147888776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 da 80 c3 98 80 75 0c 20 8d 64 24 04 66 0f b6 d8}  //weight: 10, accuracy: High
        $x_10_2 = {fe c6 80 e2 0b 8a 06 d2 f2 d0 c2 28 d8 3c c4}  //weight: 10, accuracy: High
        $x_1_3 = "GmXOjkJJ" ascii //weight: 1
        $x_1_4 = "P.vmp0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GMH_2147888783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GMH!MTB"
        threat_id = "2147888783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 d3 80 cb 65 0f bd df 80 75 0c 20 66 0f b6 d9}  //weight: 10, accuracy: High
        $x_10_2 = {88 04 24 89 44 24 ?? c7 44 24 ?? 88 af 81 4a c7 44 24 ?? 38 79 fe cc 88 74 24 ?? c6 04 24 45 ff 74 24}  //weight: 10, accuracy: Low
        $x_1_3 = ".vmp0" ascii //weight: 1
        $x_1_4 = ".vmp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_RPX_2147890034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.RPX!MTB"
        threat_id = "2147890034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff ff ff ff 10 6a 40 68 00 10 00 00 68 ?? ?? ?? 00 6a 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_RPX_2147890034_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.RPX!MTB"
        threat_id = "2147890034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iewebbc.exe" wide //weight: 1
        $x_1_2 = "taskkill /f /im" wide //weight: 1
        $x_1_3 = "PlanShell" wide //weight: 1
        $x_1_4 = "Wscript.shell" wide //weight: 1
        $x_1_5 = "*.lnk*" wide //weight: 1
        $x_1_6 = "2345.com/?kabcde" wide //weight: 1
        $x_1_7 = "2345Explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_AD_2147890366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.AD!MTB"
        threat_id = "2147890366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 44 79 08 8b d0 c7 45 fc 00 30 00 00 81 e2 00 f0 00 00 66 3b 55 fc 74 ?? c7 45 fc 00 a0 00 00 66 3b 55 fc 75 ?? 25 ff 0f 00 00 03 01 01 34 18 47 3b 7d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_RPY_2147892701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.RPY!MTB"
        threat_id = "2147892701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 85 c0 74 0f 33 c0 50 50 50 50 50 e8 4a 00 00 00 83 c4 14 8b 45 fc 69 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_NA_2147893283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.NA!MTB"
        threat_id = "2147893283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 64 fe ff ff c7 45 14 ?? ?? ?? ?? e9 e8 02 00 00 8b 45 ?? 39 45 f8 75 ec 83 f9 ff 0f 84 d7 02 00 00 8b 45 10}  //weight: 5, accuracy: Low
        $x_1_2 = "WebM Project VP8 Encoder v0.9.5-2-g755e2a2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GNU_2147895379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GNU!MTB"
        threat_id = "2147895379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 33 b5 80 2b 26 d5 77 f7 fa a2 cd 63 7e 1a 95 23 76 f9}  //weight: 10, accuracy: High
        $x_10_2 = {41 69 7c 7d ?? 8a 41 6c a1 89 dc 29 ce 83 a9}  //weight: 10, accuracy: Low
        $x_1_3 = ".vmp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_ASR_2147900737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.ASR!MTB"
        threat_id = "2147900737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {78 c3 2e 9b 82 7f 3c a9 72 52 c7 53 78 41 53 4b d6 c2 c5 1c d1 a2 f2 69 e0 ff e6 63 91 5c 4b 6f e3 40 d9 8a 6b b9 ed c3}  //weight: 2, accuracy: High
        $x_2_2 = {4e 95 2d 7d 93 96 42 b2 7a 8e 48 5f 83 76 22 34 22 bd 32 c9 25 02 04 b0 76 2b 31 23 1d 22 24 ff e0 86 72 e1 0d 12 b6 cf a3 4a 42 cd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_ND_2147901319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.ND!MTB"
        threat_id = "2147901319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 be 02 00 00 32 db 88 5d e7 83 65 fc ?? e8 d5 f9 ff ff 88 45 dc a1}  //weight: 5, accuracy: Low
        $x_1_2 = "nJ0MzIuZGxs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_SPD_2147901613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.SPD!MTB"
        threat_id = "2147901613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {80 f1 56 88 88 ?? ?? ?? ?? 8a 88 ?? ?? ?? ?? 84 c9 74 0e}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GXZ_2147903337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GXZ!MTB"
        threat_id = "2147903337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 99 f7 7d f8 8b 4d 08 53 6a 01 8d 45 ff 6a 01 50 8a 14 0a 30 55 ff e8 ?? ?? ?? ?? 83 c4 10 46 57 e8 ?? ?? ?? ?? 83 c4 04 85 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_CCIA_2147909157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.CCIA!MTB"
        threat_id = "2147909157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 8b 45 f8 8b 48 24 51 8b 55 f8 8b 42 30 50 8b 4d f0 51 ff 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_HNA_2147909711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.HNA!MTB"
        threat_id = "2147909711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c netsh advfirewall firewall add rule name=\"" ascii //weight: 1
        $x_1_2 = {2e 62 61 74 00 00 00 00 3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22}  //weight: 1, accuracy: High
        $x_1_3 = {c6 45 f7 2e c6 45 f8 65 c6 45 f9 78 c6 45 fa 65 c6 45 fb 00 e8}  //weight: 1, accuracy: High
        $x_1_4 = {41 44 56 41 50 49 33 32 2e 64 6c 6c [0-5] 53 68 65 6c 6c 45 78 65 63 75 74 65 41 00 53 48 45 4c 4c 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 00 00 75 72 6c 6d 6f 6e 2e 64 6c 6c [0-5] 44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 41 00 00 57 49 4e 49 4e 45 54 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Doina_PADY_2147911302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.PADY!MTB"
        threat_id = "2147911302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Error! Another exploit instance is running" ascii //weight: 1
        $x_1_2 = "System is *NOT* vulnarable" ascii //weight: 1
        $x_1_3 = "System is *VULNARABLE* ...  pwning" ascii //weight: 1
        $x_1_4 = "Shell code executed." ascii //weight: 1
        $x_1_5 = "Got system privileges! Type whoami." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_IH_2147911776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.IH!MTB"
        threat_id = "2147911776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 35 ?? ?? ?? ?? 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 32 44 1a ?? 88 04 11 42 81 fa ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_SG_2147912599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.SG!MTB"
        threat_id = "2147912599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\auxdata.cpp" ascii //weight: 1
        $x_1_2 = "/Program Files (x86)/Sone/%s" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 31 35 39 2e 37 35 2e 32 33 37 2e 33 39 2f 68 2f [0-15] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_GPAX_2147915638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.GPAX!MTB"
        threat_id = "2147915638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e4 83 c0 01 89 45 e4 8b 4d e4 3b 4d f4 7d 18 8b 55 fc 8b 02 33 45 f8 8b 4d fc 89 01 8b 55 fc 83 c2 04 89 55 fc eb d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_YAA_2147920702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.YAA!MTB"
        threat_id = "2147920702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TnRDcmVhdGVUaHJlYWRFeA==" ascii //weight: 1
        $x_1_2 = "TnRXcml0ZVZpcnR1YWxNZW1vcnk=" ascii //weight: 1
        $x_1_3 = "TnRBbGxvY2F0ZVZpcnR1YWxNZW1vcnk=" ascii //weight: 1
        $x_1_4 = "bnRkbGwuZGxs" ascii //weight: 1
        $x_1_5 = "JVN5c3RlbVJvb3QlXFxzeXN0ZW0zMlxcbnRkbGwuZGxs" ascii //weight: 1
        $x_1_6 = "SetTosBtKbdHook" ascii //weight: 1
        $x_1_7 = "UnHookTosBtKbd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_HNL_2147921836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.HNL!MTB"
        threat_id = "2147921836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 75 74 6f 72 75 6e 2e 69 6e 66 [0-32] 5b 41 75 74 6f 52 75 6e 5d [0-16] 6f 70 65 6e 3d 2e 5c 4d 53 4f 43 61 63 68 65 5c ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 6c 73 61 73 73 2e 65 78 65 [0-16] 73 68 65 6c 6c 65 78 65 63 75 74 65 3d 2e 5c 4d 53 4f 43 61 63 68 65 5c 02 2d 03 2d 04 2d 05 2d 06 5c 6c 73 61 73 73 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_1_2 = {5c 53 79 73 74 65 6d 5c 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 [0-32] 45 78 70 6c 6f 72 65 72 2e 65 78 65 20 20 2f 6e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_MX_2147933716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.MX!MTB"
        threat_id = "2147933716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 3d 06 00 00 0f b7 f0 e8 89 73 00 00 56 50 57 68 00 00 40 00 e8 55 f0 ff ff 8b f0 e8 57 06 00 00 84 c0}  //weight: 1, accuracy: High
        $x_1_2 = "kstatio.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_MZZ_2147937613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.MZZ!MTB"
        threat_id = "2147937613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 83 fa 2c 0f 45 cb 33 db 8a 84 0d ?? ?? ?? ?? 30 04 16 42 8d 41 01 89 95 30 ff ff ff 83 f8 14 0f 4c d8 8b c2 99 3b 95 28 ff ff ff 8b 95 30 ff ff ff 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Doina_PGD_2147939517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Doina.PGD!MTB"
        threat_id = "2147939517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Doina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 0f be 06 8b 4d e4 0f b7 d0 3b 4d e8 ?? ?? 83 7d e8 ?? 8d 41 01 89 45 e4 8d 45 d4 0f 43 45 d4 66 89 14 48 33 d2 66 89 54 48}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

