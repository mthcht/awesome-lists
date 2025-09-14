rule Trojan_Win32_Zusy_SIBA_2147794234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SIBA!MTB"
        threat_id = "2147794234"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 8b f1 2b d2 [0-16] 8a 0f 8a 06 46 47 80 7d 08 ?? 88 4d ?? 0f 84 ?? ?? ?? ?? 8a ca bb ?? ?? ?? ?? [0-16] d3 c3 8a 4d 04 [0-16] 02 da [0-16] 32 c3 42 [0-16] 84 c0 0f 84 ?? ?? ?? ?? 3a c1 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AC_2147797612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AC!MTB"
        threat_id = "2147797612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e6 04 2b f1 03 b5 ?? ?? ff ff 52 03 f6 0f af de 03 9d ?? ?? ff ff 51 32 c3 88 85}  //weight: 1, accuracy: Low
        $x_1_2 = {54 0e 46 bf 0e 66 74 53 4b 5c f6 06 67 48 6a 3e 0a 72 70 64 4a 47 66 50 a6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AC_2147797612_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AC!MTB"
        threat_id = "2147797612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b d7 e8 8a ff ff ff 85 c0 74 30 8b 75 fc 33 c9 85 f6 74 1e 0f b7 04 4b 33 d2 c7 45 fc 34 00 00 00 f7 75 fc 66 8b 44 55 90 66 89 04 4b 41 3b ce 72 e2 33 c0 66 89 04 1f 40 eb 02}  //weight: 2, accuracy: High
        $x_1_2 = {57 68 30 22 40 00 53 ff d6 e8 82 f8 ff ff 68 20 32 40 00 53 85 c0 74 76 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GGL_2147799495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GGL!MTB"
        threat_id = "2147799495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4f 04 03 ce 33 0c 30 e8 ?? ?? ?? ?? 8b 47 08 8b 4f 0c 03 ce 33 0c 30}  //weight: 10, accuracy: Low
        $x_1_2 = "Process hollowing complete" ascii //weight: 1
        $x_1_3 = "svchost" ascii //weight: 1
        $x_1_4 = "pause" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CH_2147806313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CH!MTB"
        threat_id = "2147806313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kqxcstfmcndwzigvhiotcmohs.dll" ascii //weight: 1
        $x_1_2 = "Control_RunDLL" ascii //weight: 1
        $x_1_3 = "Local\\RustBacktraceMutex" ascii //weight: 1
        $x_1_4 = "akyncbgollmj" ascii //weight: 1
        $x_1_5 = "bojkfvynhhupnooyb" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_8 = "GetTickCount64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_DKL_2147808772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.DKL!MTB"
        threat_id = "2147808772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 b8 d1 e0 8b 55 bc 8d 04 10 0f b7 00 c1 e0 02 8b 55 c0 8d 04 10 8b 55 f4 8b 00 89 02 80 7d b0 00 75 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CA_2147810205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CA!MTB"
        threat_id = "2147810205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Fsoiasgiosgiosagijsd" ascii //weight: 2
        $x_2_2 = "Jiojaeoigjaiegjad" ascii //weight: 2
        $x_2_3 = "Mijfgiegfahsughsadu" ascii //weight: 2
        $x_2_4 = "OIoijsg980segiosghj" ascii //weight: 2
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CA_2147810205_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CA!MTB"
        threat_id = "2147810205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d7 09 fb 83 e7 [0-4] 09 fe f7 d3 bf [0-4] 31 c6 8b 45 [0-4] 09 f3 88 18 b4 [0-4] b3 [0-4] 2a 65 [0-4] 28 e3 be [0-4] 81 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {31 fe f7 d3 83 f6 [0-4] 89 5d}  //weight: 1, accuracy: Low
        $x_1_3 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_4 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CB_2147810511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CB!MTB"
        threat_id = "2147810511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OIoag89wgoieghasegih" ascii //weight: 2
        $x_2_2 = "OIoiajfg98ajgoiajege" ascii //weight: 2
        $x_2_3 = "Vfgoiaefgiouaeogiahejg" ascii //weight: 2
        $x_2_4 = "bvAEGOioahgiasheg" ascii //weight: 2
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AA_2147814340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AA!MTB"
        threat_id = "2147814340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 8b da c1 eb ?? 8b 07 69 f6 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 ?? 33 c8 69 c9 95 e9 d1 5b 33 f1 83 ea ?? 83 c7 ?? 4b 75 da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SIBB_2147815124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SIBB!MTB"
        threat_id = "2147815124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AWDesk" wide //weight: 1
        $x_1_2 = "ENDPOINTDLP.DLL" ascii //weight: 1
        $x_1_3 = {ba 01 00 00 00 a1 ?? ?? ?? ?? 8b 38 ff 57 0c 8b 85 ?? ?? ?? ?? 8b 16 0f b6 7c 10 ff a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 00 01 00 00 2b d0 52 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 5a 92 8b ca 99 f7 f9 03 fa 8b d7 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 95 06 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 06 ff 4d ?? 75 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SIB_2147815766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SIB!MTB"
        threat_id = "2147815766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 08 89 45 08 81 7d 08 ?? ?? ?? ?? 7f ?? 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 4d 08 83 c1 ?? 89 8d ?? ?? ?? ?? 8b 55 08 81 c2 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 45 08 05 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 4d 08 83 c1 ?? 89 8d ?? ?? ?? ?? 8b 55 08 81 c2 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 45 08 83 c0 ?? 89 85 ?? ?? ?? ?? 8b 4d 08 81 c1 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? 8b 55 08 83 c2 ?? 89 95 ?? ?? ?? ?? 8b 45 08}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fa 01 75 ?? [0-96] c6 85 ?? ?? ?? ?? 01 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ba 01 00 00 00 85 d2 74 ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CG_2147816443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CG!MTB"
        threat_id = "2147816443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Afgaoeip0fgaj390gj" ascii //weight: 2
        $x_2_2 = "Bsgiosjgoips4jg9s4jhg" ascii //weight: 2
        $x_2_3 = "OPpoaoifgaeiogfaeiogh" ascii //weight: 2
        $x_2_4 = "Uoisgoiasegoieasgiseajgi" ascii //weight: 2
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_FXB_2147817953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.FXB!MTB"
        threat_id = "2147817953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 45 c4 88 44 3e 06 8a 45 c5 88 44 3e 05 8a 45 c6 88 44 3e 04 8a 45 c7 88 44 3e 03 8a 45 c8 88 44 3e 02 8a 45 c9 88 44 3e 01 8a 45 ca 88 04 3e 8b 75 d4 81 c6 20 00 00 00 8b 7d e0 39 fe 89 75 d8 0f 85 39 fe ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BZ_2147818039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BZ!MTB"
        threat_id = "2147818039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Jiafgjiosagoishg" ascii //weight: 2
        $x_2_2 = "OHoafjiogasejgfiosaeg" ascii //weight: 2
        $x_2_3 = "POkjasdkjgsoigserugh" ascii //weight: 2
        $x_2_4 = "Rpoaeopfgaegiosjgs" ascii //weight: 2
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RPM_2147818697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RPM!MTB"
        threat_id = "2147818697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NetSh Advfirewall set allprofiles state off" ascii //weight: 1
        $x_1_2 = "ping 192.168.3.2 -n 7" ascii //weight: 1
        $x_1_3 = "curl --url" ascii //weight: 1
        $x_1_4 = "c.tenor.com" ascii //weight: 1
        $x_1_5 = "troll-trollface.gif -o" ascii //weight: 1
        $x_1_6 = "start chrome" ascii //weight: 1
        $x_1_7 = "10.0.2.15:3000/hook.js" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RPR_2147823630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RPR!MTB"
        threat_id = "2147823630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 34 81 e9 01 00 ?? ?? ?? ?? 40 3b c2 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_B_2147828321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.B!MTB"
        threat_id = "2147828321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 02 8b 56 10 8a 0c b8 2a cb 88 4d f0 3b 56 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_B_2147828321_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.B!MTB"
        threat_id = "2147828321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ea 18 20 00 00 89 55 e8 8b 45 ec 2d 3b 1a 00 00 89 45 ec 8b 4d e8 81 c1 c2 0e 00 00 89 4d e8 8b 55 f8 81 ea 53 23 00 00 89 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_A_2147829609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.A!MTB"
        threat_id = "2147829609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe 7e 07 00 00 72 e4 33 f6 ff d7 8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe 00 76 00 00 72 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_A_2147829609_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.A!MTB"
        threat_id = "2147829609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f8 81 c1 5b 05 00 00 89 4d f8 8b 55 f8 81 ea 4d 07 00 00 89 55 f8 8b 45 e8 2d 06 09 00 00 89 45 e8 8b 4d fc 81 e9 06 02 00 00 89 4d fc 8b 55 ec 81 c2 6e 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RA_2147829998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RA!MTB"
        threat_id = "2147829998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 82 ?? ?? ?? ?? 03 c1 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c1 83 e0 03 0f b6 80 ?? ?? ?? ?? 30 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_R_2147831008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.R!MTB"
        threat_id = "2147831008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 f9 6b c0 2b 6b c0 3b 6b f0 27 8b 45 0c 8b 4d f0 0f be 14 08 31 f2 88 14 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_R_2147831008_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.R!MTB"
        threat_id = "2147831008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 04 06 c1 e0 06 be 04 00 00 00 c1 e6 00 8b 7d fc 8b 34 37 c1 ee 08 33 c6 8b 75 fc 8b 34 16 03 f0 8b 45 f8 33 d2 f7 75 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EH_2147832072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EH!MTB"
        threat_id = "2147832072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {3f 50 57 89 e7 81 c7 04 00 00 00 83 ef 04 87 3c 24 8b 24 24 89 04 24 89 2c 24 58 e9 0c e3 ff ff ff 34 24 5b 53 54 5b 81 c3 04 00 00 00 81 c3 04 00 00 00 87 1c 24}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EH_2147832072_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EH!MTB"
        threat_id = "2147832072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HamrhG7IOF6AQl4kBs1Afq3sv3NqxGGg=" ascii //weight: 1
        $x_1_2 = "WAhgSJlwvbAgLQrDqyjlNHP" ascii //weight: 1
        $x_1_3 = "wWZEErRBYamalmCEptOgqyN" ascii //weight: 1
        $x_1_4 = "nqjiTvBgoRQnFMDaKxXvXCT" ascii //weight: 1
        $x_1_5 = "DnsHostnameToComputerNameW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MA_2147832238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MA!MTB"
        threat_id = "2147832238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb 7e d8 ca d8 c3 d8 e7 89 12 d8 d7 d8 cd d8 ce d8 db d8 c0 d8 c0 89 11 d8 ed d8 d9 d8 df d8 c3 d8 d9 d8 e5 d8 c3 d8 ed d8 c1 d8 c4 89 0a d8 c3}  //weight: 10, accuracy: High
        $x_10_2 = "FGBHNJMK.DLL" ascii //weight: 10
        $x_1_3 = "FfgbHgybh" ascii //weight: 1
        $x_1_4 = "FgbyhnKjgv" ascii //weight: 1
        $x_1_5 = "TtfvygbKhbgf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MA_2147832238_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MA!MTB"
        threat_id = "2147832238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hiosjh98w4goiw4jserjh" ascii //weight: 2
        $x_2_2 = "iosog3498gsejoiseijh" ascii //weight: 2
        $x_2_3 = "fork5.dll" ascii //weight: 2
        $x_2_4 = "shibosjeg984gioserhjser" ascii //weight: 2
        $x_2_5 = "siogsjriog498gsjioehje" ascii //weight: 2
        $x_1_6 = "SetThreadAffinityMask" ascii //weight: 1
        $x_1_7 = "GetProcessWorkingSetSizeEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MB_2147832324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MB!MTB"
        threat_id = "2147832324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb 38 d8 c2 d8 ea d8 ca d8 d1 d8 d0 d8 d4 89 10 d8 d1 d8 c0 88 10 d8 c5 d8 e1 d8 ec d8 c8 d8 db 8a 0c d8 d4 d8 df d8 cd d8 e1 d8 e2 d8 c7 d8 d8}  //weight: 10, accuracy: High
        $x_10_2 = "FGBHNJMK.DLL" ascii //weight: 10
        $x_1_3 = "FfgbHgybh" ascii //weight: 1
        $x_1_4 = "FgbyhnKjgv" ascii //weight: 1
        $x_1_5 = "TtfvygbKhbgf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MB_2147832324_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MB!MTB"
        threat_id = "2147832324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NiksrjghsrojAisjhirjh" ascii //weight: 2
        $x_2_2 = "NofdohjAdhodrjhorshj" ascii //weight: 2
        $x_2_3 = "OjsjsofjAsjhgsrijhr" ascii //weight: 2
        $x_1_4 = "SetProcessPriorityBoost" ascii //weight: 1
        $x_1_5 = "SetThreadLocale" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MC_2147832335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MC!MTB"
        threat_id = "2147832335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb 52 d8 e2 d8 dc d8 d2 d8 c3 d8 de d8 e0 d8 dd d8 e4 8a 13 d8 c5 d8 e9 d8 e7 89 0b d8 c2 d8 d7 d8 e7 d8 c6 d8 d8 d8 ee d8 c9 d8 e5 d8 c8 8a 0b}  //weight: 10, accuracy: High
        $x_10_2 = "ASDFGH.DLL" ascii //weight: 10
        $x_1_3 = "RcrtyvJbin" ascii //weight: 1
        $x_1_4 = "EctryvKuybin" ascii //weight: 1
        $x_1_5 = "GyvtubKyvb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MD_2147832349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MD!MTB"
        threat_id = "2147832349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MONIBUYVTY.DLL" ascii //weight: 10
        $x_1_2 = "LhbugvyUfyctd" ascii //weight: 1
        $x_1_3 = "MnibFct" ascii //weight: 1
        $x_1_4 = "OnjihGcrt" ascii //weight: 1
        $x_1_5 = "GetCurrentProcessId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ME_2147832444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ME!MTB"
        threat_id = "2147832444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "TRCYTVUBI.DLL" ascii //weight: 10
        $x_1_2 = "RtyvgbKbh" ascii //weight: 1
        $x_1_3 = "KnjihbEftvg" ascii //weight: 1
        $x_1_4 = "LbhgvOjhbg" ascii //weight: 1
        $x_1_5 = "GetCurrentThreadId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MF_2147832445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MF!MTB"
        threat_id = "2147832445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DRCTF.DLL" ascii //weight: 10
        $x_1_2 = "PnhubgyEctyv" ascii //weight: 1
        $x_1_3 = "RtcfvyKnbg" ascii //weight: 1
        $x_1_4 = "TsxrdPnhbug" ascii //weight: 1
        $x_1_5 = "WaitForSingleObject" ascii //weight: 1
        $x_1_6 = "GetCurrentThreadId" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RE_2147834221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RE!MTB"
        threat_id = "2147834221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 d2 8b c1 6a 37 5e f7 f6 83 c2 32 66 31 54 4d ac 41 83 f9 17 7c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RE_2147834221_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RE!MTB"
        threat_id = "2147834221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 6f 72 6b 38 2e 64 6c 6c 00 4a 69 61 6a 6f 69 66 6a 61 65 67 65 61 69 6a 67 64 6a 00 4c 61 69 6f 66 67 6a 61 65 6f 69 67 65 61 67 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RE_2147834221_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RE!MTB"
        threat_id = "2147834221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 04 3a 8b 18 89 ce 31 de 89 30 8d 47 04 89 c7 3b 7d fc 72 eb}  //weight: 1, accuracy: High
        $x_1_2 = "gwY9bMUccggghQF4juBKQ7IouGkyPRpeip5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RE_2147834221_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RE!MTB"
        threat_id = "2147834221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 8b 08 89 4d e8 8b 55 f4 8b 02 c1 e0 06 8b 4d f4 8b 11 c1 ea 08 33 c2 8b 4d f4 8b 09 03 c8 8b 45 fc 33 d2 f7 75 ec 8b 45 08 03 0c 90 03 4d fc 8b 55 f0 8b 02 2b c1 8b 4d f0 89 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RF_2147834589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RF!MTB"
        threat_id = "2147834589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 52 83 7c ?? 14 08 8d 04 ?? 72 02 8b 00 8d 4c 24 ?? 51 8d 4c 24 ?? 51 6a 00 6a 00 68 04 00 00 08 6a 00 6a 00 6a 00 6a 00 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RF_2147834589_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RF!MTB"
        threat_id = "2147834589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 06 8b 55 ?? c1 ea 08 33 ca 03 4d ?? 8b 45 ?? 33 d2 f7 75 ec 8b 45 ?? 03 0c ?? 03 4d ?? 8b 55 f0 2b d1 89 55 f0 8b 45 f0 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RG_2147834622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RG!MTB"
        threat_id = "2147834622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 0f 43 cf 33 d2 f7 74 24 ?? 8a 04 0a 30 04 33 43 a1 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 2b c6 3b d8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RG_2147834622_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RG!MTB"
        threat_id = "2147834622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 65 fc 00 8b c6 8a 96 ?? ?? ?? 00 83 e0 03 6a 00 88 55 bf 8a 88 ?? ?? ?? 00 32 ca 8d 04 11 88 86 ?? ?? ?? 00 e8 ?? ?? ?? ?? 8a 45 bf 28 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RI_2147837689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RI!MTB"
        threat_id = "2147837689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 ec b9 21 00 00 c7 45 e4 00 00 00 00 c7 45 f4 c0 13 00 00 c7 45 f8 c1 13 00 00 8b 55 f4 2b 55 f8 89 55 f4 c7 45 fc 00 00 00 00 c7 45 e8 29 21 00 00 8b 45 f8 2b 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RJ_2147837690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RJ!MTB"
        threat_id = "2147837690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 08 03 4d e4 0f be 11 0f be 45 14 33 d0 88 55 eb 8b 4d e4 83 c1 01 89 4d e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RJ_2147837690_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RJ!MTB"
        threat_id = "2147837690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 f4 41 02 00 00 c7 45 fc 03 1b 00 00 8b 45 f4 03 45 fc 89 45 f4 c7 45 f0 00 00 00 00 8b 4d fc 03 4d f4 89 4d fc 8b 55 f0 2b 55 f4 89 55 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RJ_2147837690_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RJ!MTB"
        threat_id = "2147837690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4c 24 14 8d 54 24 10 8b c1 c1 e8 03 c1 e1 05 0b c1 f7 d0 89 44 24 14}  //weight: 5, accuracy: High
        $x_1_2 = "34f4bcbcd49c7cd46c8e8c8496b47c8e846cc4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RJ_2147837690_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RJ!MTB"
        threat_id = "2147837690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://server.0569.microsoftmiddlename.tk" ascii //weight: 3
        $x_2_2 = "http://imgcache.cloudservicesdevc.tk" ascii //weight: 2
        $x_1_3 = "ProgramData/setting.ini" ascii //weight: 1
        $x_1_4 = "HipsTray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RD_2147839421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RD!MTB"
        threat_id = "2147839421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 65 00 88 07 00 e0 0f b6 f8 8b 44 24 14 8a 00 43 32 04 37 8b 3c 24 ff 44 24 14 47 88 43 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RD_2147839421_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RD!MTB"
        threat_id = "2147839421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 74 72 62 79 74 6e 75 79 6b 69 2e 64 6c 6c 00 74 72 62 64 79 74 6a 75 6e 00 64 74 72 62 79 74 6e 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RD_2147839421_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RD!MTB"
        threat_id = "2147839421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 b9 82 00 00 00 bf b0 79 44 01 68 2b 03 00 00 f3 ab e8 0b f6 ff ff 8b 0d e0 a4 65 00 03 c8 83 c4 04 89 0d e0 a4 65 00 e8 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RD_2147839421_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RD!MTB"
        threat_id = "2147839421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 e8 0f b6 44 2c 30 88 44 1c 30 88 4c 2c 30 0f b6 44 1c 30 03 c2 0f b6 c0 0f b6 44 04 30 32 87 ?? ?? ?? ?? 88 44 3c 1c 47 83 ff 14 72 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZ_2147840877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZ!MTB"
        threat_id = "2147840877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 a8 f2 04 10 53 89 44 24 44 ff d6 68 b8 f2 04 10 53 89 44 24 48 ff d6 68 c8 f2 04 10 53 89 44 24 4c ff d6 8b 5c 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBAT_2147842124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBAT!MTB"
        threat_id = "2147842124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 6f 72 6b 32 2e 64 6c 6c 00 50 61 73 64 6f 67 6a 73 65 6f 68 65 6a 68 00 55 59 61 69 73 64 67 69 6a 41 68 73 68 64 68 00 6a 6f 65 67 6f 41 6a 6f 61 6a 67 69 65 6a 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RB_2147842223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RB!MTB"
        threat_id = "2147842223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 7e 07 00 00 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 3b ca 72 ea 53 56 57 6a 40 68 00 30 00 00 52 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BO_2147842318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BO!MTB"
        threat_id = "2147842318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CsoijhgirodAosfjhrhr" ascii //weight: 2
        $x_2_2 = "Ksdgowsrjhsirjhsrhj" ascii //weight: 2
        $x_2_3 = "LshdgsikdjgoiQjsfohjf" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBAU_2147842357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBAU!MTB"
        threat_id = "2147842357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 4e 69 73 66 64 6a 69 68 73 72 6a 6f 68 41 6f 63 76 62 6f 64 6a 72 00 51 6f 78 63 76 6f 73 67 6a 72 67 68 73 64 72 6f 68 6a 72 41 61 66 66 66 00 58 69 67 64 6f 70 70 64 70 76 6f 6b 6a 72 6f 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPL_2147842407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPL!MTB"
        threat_id = "2147842407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MoraleAbundant" ascii //weight: 1
        $x_1_2 = "TortureShare" ascii //weight: 1
        $x_1_3 = "TumourCrop" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RK_2147842704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RK!MTB"
        threat_id = "2147842704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 11 84 24 ?? ?? ?? ?? c7 84 24 ?? ?? ?? ?? ?? ?? ?? ?? 0f 28 05 ?? ?? ?? ?? 0f 11 84 24 ?? ?? ?? ?? 66 ?? 8a 84 24 08 01 00 00 30 84 0c 09 01 00 00 41 81 f9 d2 00 00 00 72 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EC_2147842708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EC!MTB"
        threat_id = "2147842708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b c1 c1 c0 10 2b c1 c1 e8 10 40 c3 33 c0 40 2b c6 2b c2 c3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EC_2147842708_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EC!MTB"
        threat_id = "2147842708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 4d 10 8b 55 14 80 3a 00 74 f8 90 90 90 90 ac 32 02 aa 90 90 90 90 42 49 85 c9 75 e9}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EC_2147842708_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EC!MTB"
        threat_id = "2147842708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WORK_20160328175600761943" ascii //weight: 1
        $x_1_2 = "c:\\\\Destro" ascii //weight: 1
        $x_1_3 = "othinf" ascii //weight: 1
        $x_1_4 = "NkGyViAJkwHiLG" ascii //weight: 1
        $x_1_5 = "AJkwHiLGY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EC_2147842708_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EC!MTB"
        threat_id = "2147842708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VHJpYWwgcGVyaW9kIGhhcyBleHBpcmVkLg==" ascii //weight: 1
        $x_1_2 = "Q2hpbGthdEJ1bmRsZQ==" ascii //weight: 1
        $x_1_3 = "TUFJTA==" ascii //weight: 1
        $x_1_4 = "Q2hpbGthdE1haWw=" ascii //weight: 1
        $x_1_5 = "INJECT_ENJOYERS.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EC_2147842708_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EC!MTB"
        threat_id = "2147842708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FunFunFun" ascii //weight: 1
        $x_1_2 = "shample.ru" ascii //weight: 1
        $x_1_3 = "Shample.pdb" ascii //weight: 1
        $x_1_4 = "GetTempPathW" ascii //weight: 1
        $x_1_5 = "C:\\TEMP\\system.exe" ascii //weight: 1
        $x_1_6 = "C:\\TEMP\\SHAMple.dat" ascii //weight: 1
        $x_1_7 = "Software\\SHAMple" ascii //weight: 1
        $x_1_8 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EM_2147842976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EM!MTB"
        threat_id = "2147842976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 d3 2b f9 2b c3 2b d1 33 cf 33 fa}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EM_2147842976_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EM!MTB"
        threat_id = "2147842976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 02 4b 81 c2 04 00 00 00 bb 90 ae f3 c2 21 d9 39 fa 75 e7 21 f3 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EM_2147842976_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EM!MTB"
        threat_id = "2147842976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d c0 33 c0 8b 5d 0c c7 42 40 00 00 00 00 8a 04 10 30 04 19 41 ff 42 40 8b 42 40}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EM_2147842976_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EM!MTB"
        threat_id = "2147842976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 84 34 e0 00 00 00 88 94 3c e0 00 00 00 0f b6 b4 34 e0 00 00 00 03 f2 8b 7d 08 81 e6 ff 00 00 00 8b 94 24 30 02 00 00 8a 04 0f 32 84 34 e0 00 00 00 88 04 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EM_2147842976_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EM!MTB"
        threat_id = "2147842976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exodus\\exodus.wallet" ascii //weight: 1
        $x_1_2 = "Ethereum\\keystore" ascii //weight: 1
        $x_1_3 = "Moonchild Productions\\Pale Moon" ascii //weight: 1
        $x_1_4 = "Outlook\\9375CFF0413111d3B88A00104B2A6676" ascii //weight: 1
        $x_1_5 = "NNTP Email Address" ascii //weight: 1
        $x_1_6 = "cfbpiemnkdpom" ascii //weight: 1
        $x_1_7 = "SMTP User Name" ascii //weight: 1
        $x_1_8 = "Grabber" ascii //weight: 1
        $x_1_9 = "gecko_browsers" ascii //weight: 1
        $x_1_10 = "Wallets" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EM_2147842976_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EM!MTB"
        threat_id = "2147842976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SimpleProgramDebugger" ascii //weight: 1
        $x_1_2 = "HeapMemView" ascii //weight: 1
        $x_1_3 = "DLLExportViewer" ascii //weight: 1
        $x_1_4 = "You are banned, contact an administrator!" ascii //weight: 1
        $x_1_5 = "Downloads\\uhloader_[unknowncheats.me]_.dll" ascii //weight: 1
        $x_1_6 = "Unwanted programs detected" ascii //weight: 1
        $x_1_7 = "Suspended the process for bypass" ascii //weight: 1
        $x_1_8 = "thread manipulation attempt [Inject] v2" ascii //weight: 1
        $x_1_9 = "\\Xor_Plus\\Splash\\Xor-hack.bmp" ascii //weight: 1
        $x_1_10 = "Data/Local/z.jpeg" ascii //weight: 1
        $x_1_11 = "/BanHwID/BanHwID.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EN_2147843011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EN!MTB"
        threat_id = "2147843011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GETSERVER2.0" ascii //weight: 1
        $x_1_2 = "An unsupported operation was attempted" ascii //weight: 1
        $x_1_3 = "ColorPickerDemo.EXE" wide //weight: 1
        $x_1_4 = "CreateThread" ascii //weight: 1
        $x_1_5 = "HrCg@b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BP_2147843146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BP!MTB"
        threat_id = "2147843146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BsiserhjAisrjohjrih" ascii //weight: 2
        $x_2_2 = "HsrjisrjAjsrihjr" ascii //weight: 2
        $x_2_3 = "OsjigjsrAjiejgiesj" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BQ_2147843284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BQ!MTB"
        threat_id = "2147843284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BsohjirjAufiseighjseih" ascii //weight: 2
        $x_2_2 = "MshirAijseihjerh" ascii //weight: 2
        $x_2_3 = "OsojgeiherAijseijeh" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BR_2147843288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BR!MTB"
        threat_id = "2147843288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BiosjhoisfjAoisjihjre" ascii //weight: 2
        $x_2_2 = "KsoigjsAjshjrijh" ascii //weight: 2
        $x_2_3 = "LsiorhjisrIjijhr" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BS_2147843614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BS!MTB"
        threat_id = "2147843614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Aogioswioghswoihjsrjh" ascii //weight: 2
        $x_2_2 = "KoiosdfhgiiIijshgisrjh" ascii //weight: 2
        $x_2_3 = "kvjpsgjwseiogjwiojhg" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NEAA_2147843625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NEAA!MTB"
        threat_id = "2147843625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 82 fc ad ?? 00 32 c1 41 88 84 15 a0 fb ff ff 81 e1 ff 00 00 80 79 08 49 81 c9 00 ff ff ff 41 42 83 fa 1b 7c da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BT_2147843672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BT!MTB"
        threat_id = "2147843672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Iohsoprjghiorjhgiorj" ascii //weight: 2
        $x_2_2 = "Lososjrihsrjhisjig" ascii //weight: 2
        $x_2_3 = "hjsgisegjoighjseihe" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ABQP_2147843690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ABQP!MTB"
        threat_id = "2147843690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BsjiogsjgioAJIjsrgh" ascii //weight: 2
        $x_2_2 = "Kjsjoighsjrhgisrj" ascii //weight: 2
        $x_2_3 = "Pjiosgjiuosjghosejghi" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GHC_2147843770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GHC!MTB"
        threat_id = "2147843770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 34 24 83 c4 04 e8 ?? ?? ?? ?? 31 33 89 c0 89 f8 43 39 d3 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ABRL_2147844129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ABRL!MTB"
        threat_id = "2147844129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Jseiopsgopegiosjiohh" ascii //weight: 2
        $x_2_2 = "Lopagioeoigijiejhes" ascii //weight: 2
        $x_2_3 = "fork5.dll" ascii //weight: 2
        $x_2_4 = "Poaiosjvibiniopqpdo" ascii //weight: 2
        $x_2_5 = "ohnbipAokvunowpvhvorj" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RC_2147844213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RC!MTB"
        threat_id = "2147844213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 48 3e 00 00 50 b8 cb 6d 00 00 b8 2f 18 00 00 58 58 52 ba da 16 00 00 51 b9 55 78 00 00 b9 0f 22 00 00 59 5a 52 52 ba 79 18 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RC_2147844213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RC!MTB"
        threat_id = "2147844213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 02 6a 00 6a 02 e8 ?? ?? fe ff 6a 02 6a 00 6a 02 e8 ?? ?? fe ff 6a 02 6a 00 6a 02 e8 ?? ?? fe ff}  //weight: 5, accuracy: Low
        $x_1_2 = "jhS7h4HsY3gh65hsW3334" ascii //weight: 1
        $x_1_3 = "CCC Crypter" ascii //weight: 1
        $x_1_4 = "XEAZERTACQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ABRO_2147844223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ABRO!MTB"
        threat_id = "2147844223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Aosoigrsiohiojhsegg" ascii //weight: 2
        $x_2_2 = "Bosdgiosigjsewihjseh" ascii //weight: 2
        $x_2_3 = "Bosgoisroigwsoihjehe" ascii //weight: 2
        $x_2_4 = "Ooiejgiowsejgoisjhs" ascii //weight: 2
        $x_2_5 = "fork5.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RDA_2147844496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RDA!MTB"
        threat_id = "2147844496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bosiogjioejhgeh" ascii //weight: 1
        $x_1_2 = "Fodopkwoipgoiwej" ascii //weight: 1
        $x_1_3 = "Iuiogiosejighseih" ascii //weight: 1
        $x_1_4 = "sfiogjiogjAisriosejh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BU_2147845830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BU!MTB"
        threat_id = "2147845830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Bioesguiosegheasiug" ascii //weight: 2
        $x_2_2 = "JKkaejgfisejioegoseji" ascii //weight: 2
        $x_2_3 = "osidfgiuoewsgoiewjghie" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BX_2147845938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BX!MTB"
        threat_id = "2147845938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Uioesgweiogweigjeoiwajg" ascii //weight: 2
        $x_2_2 = "VseiugseoghAhosghseh" ascii //weight: 2
        $x_2_3 = "mvboisrgsejgoiesjhiij" ascii //weight: 2
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPH_2147846392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPH!MTB"
        threat_id = "2147846392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 0e 32 54 24 0c 66 d1 6c 24 0c 83 e0 01 85 c0 8b 44 24 0c 88 11 74 09 35 ?? ?? ?? ?? 89 44 24 0c 83 c1 01 83 ef 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GHG_2147846538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GHG!MTB"
        threat_id = "2147846538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 d8 85 40 00 5a b9 ?? ?? ?? ?? 09 c0 e8 ?? ?? ?? ?? 89 c1 31 16 81 c6 ?? ?? ?? ?? 01 c1 49 39 fe 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CREL_2147846740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CREL!MTB"
        threat_id = "2147846740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 04 13 30 c8 88 44 24 24 89 cf d1 ?? 81 e7 ?? ?? ?? ?? 89 fb 81 f3 ?? ?? ?? ?? f6 c1 ?? 0f 44 df 8b 44 24 28 8a 4c 24 24 88 0c 10 8b 44 24 28 42 89 d9 8b 5c 24 34 39 d6 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BY_2147847521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BY!MTB"
        threat_id = "2147847521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Kjiajfgiaeghdaih" ascii //weight: 3
        $x_3_2 = "Naeuigohaegihdd" ascii //weight: 3
        $x_1_3 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GJM_2147848359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GJM!MTB"
        threat_id = "2147848359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cdn.discordapp.com/attachments/947450701154517052" ascii //weight: 1
        $x_1_2 = "\\yuki-module.dll" ascii //weight: 1
        $x_1_3 = "\\dont_load.txt" ascii //weight: 1
        $x_1_4 = "\\inject_version.txt" ascii //weight: 1
        $x_1_5 = "\\lightcord-temp\\extract.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_INI_2147848436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.INI!MTB"
        threat_id = "2147848436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b cd 8d 44 24 ?? 89 54 24 ?? e8 33 fe ff ff 8b 44 24 20 31 44 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 8b 44 24 10 33 44 24 24 89 44 24 10 2b f0 8d 44 24 28 e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GJN_2147848808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GJN!MTB"
        threat_id = "2147848808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 10 89 6c 24 10 8d 6c 24 10 29 c4 53 56 57 a1 2c b1 40 00 31 45 fc}  //weight: 10, accuracy: High
        $x_1_2 = ".ropf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPT_2147849140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPT!MTB"
        threat_id = "2147849140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 95 9f fc ff ff 0f b6 85 9f fc ff ff 03 85 a0 fc ff ff 88 85 9f fc ff ff 0f b6 8d 9f fc ff ff c1 f9 02 0f b6 95 9f fc ff ff c1 e2 06 0b ca 88 8d 9f fc ff ff 0f b6 85 9f fc ff ff 83 c0 39 88 85 9f fc ff ff 8b 8d a0 fc ff ff 8a 95 9f fc ff ff 88 54 0d 8c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GJT_2147849967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GJT!MTB"
        threat_id = "2147849967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 38 81 c3 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 d0 75 ?? c3 68 68 ?? ?? ?? ?? 8d 3c 39 8b 3f 09 db}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBFD_2147850099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBFD!MTB"
        threat_id = "2147850099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 34 1f 40 00 10 f0 70 00 00 ff ff ff 08 00 00 00 01 00 00 00 08 00 00 00 e9 00 00 00 70 21 40 00 b4 11 40 00 a8 10 40 00 78}  //weight: 1, accuracy: High
        $x_1_2 = "ZDXBWDPPXTUAYAFREVRBDZHNFYYXQVBU" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GJU_2147850646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GJU!MTB"
        threat_id = "2147850646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 f8 05 83 e6 1f c1 e6 06 03 34 85 ?? ?? ?? ?? 8b 45 e4 8b 00 89 06 8d 46 0c 8a 03 88 46 04 68 a0 0f 00 00 50}  //weight: 10, accuracy: Low
        $x_1_2 = "@.ropf" ascii //weight: 1
        $x_1_3 = "\\PostInstall\\release\\PostInstall.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CK_2147851284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CK!MTB"
        threat_id = "2147851284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Continenthim" ascii //weight: 2
        $x_2_2 = "Coverlot" ascii //weight: 2
        $x_2_3 = "Majorthree" ascii //weight: 2
        $x_2_4 = "Wavespot" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CM_2147851411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CM!MTB"
        threat_id = "2147851411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Yitisagiasegaisdokx" ascii //weight: 2
        $x_2_2 = "oioaidfjaoeighauehg" ascii //weight: 2
        $x_2_3 = "Fgisoegioaegjadf" ascii //weight: 2
        $x_2_4 = "Foiadsovcijasgfiag" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SL_2147851869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SL!MTB"
        threat_id = "2147851869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MRCorporation.exe" ascii //weight: 1
        $x_1_2 = "MRCorporation.Properties" ascii //weight: 1
        $x_1_3 = "MRCorporation.Properties.Resources.resources" ascii //weight: 1
        $x_1_4 = "So40Q2q6Kx3JJw1K" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMAC_2147852051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMAC!MTB"
        threat_id = "2147852051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 8d bc 24 ?? ?? ?? ?? 03 fb 0f b6 07 03 c6 25 ?? ?? ?? ?? 79 07 48 0d ?? ?? ?? ?? 40 8d b4 24 ?? ?? ?? ?? 89 44 24 10 03 f0 56 57 e8 ?? ?? ?? ?? 0f b6 06 83 c4 08 0f b6 0f 8b 74 24 10 03 c8 0f b6 c1 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBHK_2147852105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBHK!MTB"
        threat_id = "2147852105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HtvybuFtvyb" ascii //weight: 1
        $x_1_2 = "KnubyFtvyb" ascii //weight: 1
        $x_1_3 = "DtryvbhYcyvghbj" ascii //weight: 1
        $x_1_4 = "UrctvKtcvyb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RDB_2147852364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RDB!MTB"
        threat_id = "2147852364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 24 28 23 d1 0f af 15 44 a0 40 00 32 c3 89 0d 48 a0 40 00 2a c3 89 15 4c a0 40 00 32 c3 83 c4 0c 02 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBHO_2147852476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBHO!MTB"
        threat_id = "2147852476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 75 69 79 75 6d 74 79 6e 72 2e 64 6c 6c 00 75 69 79 75 74 79 64 72 00 75 69 66 75 6d 74 64 79 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBHP_2147852694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBHP!MTB"
        threat_id = "2147852694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 64 6b 72 68 6e 66 6c 64 2e 64 6c 6c 00 75 6a 72 6e 66 6a 64 6b 66 00 6b 66 6c 72 68 64 6e 62 6b 00 72 75 6a 67 66 6b 69 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZ_2147852763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZ!MTB"
        threat_id = "2147852763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a3 60 c6 40 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? 33 c0 a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? ba 94 b0 40 00 8b c3 e8 b1 e8 ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZ_2147852763_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZ!MTB"
        threat_id = "2147852763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 cc 4c b3 0a 81 aa ?? ?? ?? ?? 45 a8 93 fb 0c 67 13 4b ?? 7e f3 ff b3 9f bb b9 b5}  //weight: 5, accuracy: Low
        $x_5_2 = {31 cf 44 e2 23 86 f3 69 7d e2 a0 3d 7f 43 04 02 45 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZ_2147852763_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZ!MTB"
        threat_id = "2147852763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 6f fd ff ff 8b 4c 24 ?? 8b 54 24 08 85 c9 88 48 14 89 ?? ?? ?? ?? ?? 75 09 6a fd ff 15 2c 32}  //weight: 5, accuracy: Low
        $x_1_2 = "pro.partria.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZ_2147852763_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZ!MTB"
        threat_id = "2147852763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {80 3f 23 75 f2 8b 07 8a 5f 04 66 c1 e8 08 c1 c0 10 86 c4 29 f8 80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 50 5f 00}  //weight: 3, accuracy: High
        $x_2_2 = {83 c7 04 83 e9 04 77 f1 01 cf e9 2c ff ff ff 5e 89 f7 b9 d0 ac 00 00 8a 07 47 2c e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZ_2147852763_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZ!MTB"
        threat_id = "2147852763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 41 08 c7 41 04 00 00 00 00 89 51 0c 8b 06 89 41 10 8b 45 f8 89 0e ff 00 ff 75 fc ff d3 8b 77 50 6a 20}  //weight: 3, accuracy: High
        $x_1_2 = "GetNativeSystemInfo" ascii //weight: 1
        $x_1_3 = "WSASend" ascii //weight: 1
        $x_1_4 = ":J:O:X:V:S:Y:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZ_2147852763_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZ!MTB"
        threat_id = "2147852763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "antianalysier started" ascii //weight: 2
        $x_1_2 = "encodedPayload_password" ascii //weight: 1
        $x_1_3 = "( i dont love u, bro(((" ascii //weight: 1
        $x_1_4 = "@ why u reverse my stub?((" ascii //weight: 1
        $x_1_5 = "POnPaPic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBHQ_2147852860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBHQ!MTB"
        threat_id = "2147852860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FrhtjykuDefgrhtjy" ascii //weight: 1
        $x_1_2 = "SfghtyjFhtjyku" ascii //weight: 1
        $x_1_3 = "rgthryjt.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GMC_2147853384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GMC!MTB"
        threat_id = "2147853384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 fc 83 c4 14 48 89 35 ?? a9 a5 00 5f 5e a3 8c a9 a5 00 5b}  //weight: 10, accuracy: Low
        $x_10_2 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 38 b0 a5 00 89 35 a8 a9 a5 00 8b fe 38 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GMC_2147853384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GMC!MTB"
        threat_id = "2147853384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 ?? b0 a5 00 89 35 ?? a9 a5 00 8b fe 38 18}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 fc 83 c4 14 48 89 35 ?? a9 a5 00 5f 5e a3 ?? a9 a5 00 5b c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GMC_2147853384_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GMC!MTB"
        threat_id = "2147853384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 8b 45 fc 8d 04 86 50 56 57 e8 ?? ?? ?? ?? 8b 45 fc 83 c4 14 48 89 35 a8 bc 45 01 5f 5e a3 a4 bc 45 01 5b c9 c3}  //weight: 10, accuracy: Low
        $x_1_2 = "SteamService.exe" ascii //weight: 1
        $x_1_3 = "@.i815" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GME_2147888131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GME!MTB"
        threat_id = "2147888131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 8b 55 08 56 00 f1 8b 06 83 e8 10 ?? 00 39 50 08 7d 13 85 d2 00 0f 57 8b 39 6a 01 ?? 00 ff 57 08 5f 85 c0 75 00 e8 40}  //weight: 10, accuracy: Low
        $x_1_2 = "dmcommander.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_DT_2147888639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.DT!MTB"
        threat_id = "2147888639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 ef 17 8d 44 38 0d 88 44 24 0d 30 59 0d 83 fa 0e 74}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 54 08 0a 8a 5c 08 1a c1 e2 10 80 f3 ea 74}  //weight: 1, accuracy: High
        $x_1_3 = "DdqDptdmglwMgrqoarDpooAkdR" ascii //weight: 1
        $x_1_4 = "JrUsggmwwjqNlgwsvdRpeqef|" ascii //weight: 1
        $x_1_5 = "QuiDyqihQkjkfbfUpsklg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBHX_2147888674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBHX!MTB"
        threat_id = "2147888674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 61 71 73 70 76 77 6f 2e 64 6c 6c 00 6a 6b 6e 77 61 70 75 66 6c 62 71 73 00 6b 61 72 70 76 6d 77 6c 68 69 79 6e 00 6c 76 67 73 78 70 7a 6f 74 00 7a 72 68 61 6b 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBHZ_2147888799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBHZ!MTB"
        threat_id = "2147888799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "datuorlp.dll" ascii //weight: 1
        $x_1_2 = "tyknia" ascii //weight: 1
        $x_1_3 = "wjriqplm" ascii //weight: 1
        $x_1_4 = "xzvjhqt" ascii //weight: 1
        $x_1_5 = "zkdypjhl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GMH_2147888894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GMH!MTB"
        threat_id = "2147888894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 83 e0 07 b9 ?? ?? ?? ?? 2b c8 b0 01 d2 e0 8a 0e 0a c8 88 0e 8b 74 24 20 8b 44 24 10 42 3b d0 0f 82 ?? ?? ?? ?? 8b 44 24 14 47 3b f8 0f 82}  //weight: 10, accuracy: Low
        $x_1_2 = "_fnPDFToText@8" ascii //weight: 1
        $x_1_3 = "Duldtl Eumdu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RPY_2147888902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RPY!MTB"
        threat_id = "2147888902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f0 6a 5a 56 ff 15 58 80 65 00 56 6a 00 a3 90 cd 65 00 ff 15 40 83 65 00 a1 90 cd 65 00 6a 48 50 6a 08 ff 15 ec 80 65 00 8b 35 5c 80 65 00 f7 d8 6a 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BL_2147889117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BL!MTB"
        threat_id = "2147889117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stone,I hate you!" ascii //weight: 1
        $x_1_2 = "Your disk is removed!" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" ascii //weight: 1
        $x_1_4 = "\\AutoRun.exe" ascii //weight: 1
        $x_1_5 = {45 d8 8b 55 f8 8b 4d f4 8a 54 0a ff e8 53 8b fa ff 8d 45 d8 ba dc b8 45 00 e8 26 8c fa ff 8b 45 d8 8d 55 dc e8 bb ca fa ff 8b 4d dc b2 01 a1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPN_2147889177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPN!MTB"
        threat_id = "2147889177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {da 80 b6 50 c8 01 10 c8 46 3b f7 7c f4 83 ec 10}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPAC_2147890332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPAC!MTB"
        threat_id = "2147890332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 84 1c 30 01 00 00 30 86 ?? ?? ?? ?? 46 8b 5c 24 1c 8b 54 24 10 81 fe}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPAC_2147890332_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPAC!MTB"
        threat_id = "2147890332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CAttendanceRS" ascii //weight: 1
        $x_1_2 = "ODBC;DSN=MISDB" ascii //weight: 1
        $x_1_3 = {5b 50 45 52 53 4f 4e 5d 00 00 00 00 5b 49 44 5d}  //weight: 1, accuracy: High
        $x_1_4 = "CErrandRS" ascii //weight: 1
        $x_1_5 = "CLeaveRS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPAD_2147890345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPAD!MTB"
        threat_id = "2147890345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 0e 03 c8 0f b6 c1 8b 4c 24 10 8a 84 04 14 01 00 00 30 85 ?? ?? ?? ?? 45 81 fd 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNS_2147890510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNS!MTB"
        threat_id = "2147890510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 0a 53 65 74 75 70 3d 70 64 66 2e 70 64 66 0d 0a [0-11] 53 69 6c 65 6e 74 3d 31 0d 0a}  //weight: 2, accuracy: Low
        $x_2_2 = {0d 0a 53 65 74 75 70 3d 70 64 66 2e 65 78 65 0d 0a [0-11] 53 69 6c 65 6e 74 3d 31 0d 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_HNS_2147890510_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNS!MTB"
        threat_id = "2147890510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InternetGetConnectedState" ascii //weight: 1
        $x_1_2 = {20 20 20 20 20 20 20 20 20 2e 65 78 65 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 2e 65 78 65 00 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNS_2147890510_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNS!MTB"
        threat_id = "2147890510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 68 00 65 00 6c 00 6c 00 6f 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_2 = {4e 00 61 00 6d 00 65 ?? ?? ?? ?? ?? 48 00 65 00 6c 00 6c 00 6f 00 20 00 57 00 6f 00 72 00 6c 00 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e ?? ?? ?? ?? ?? 43 00 6c 00 69 00 65 00 6e 00 20 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 52 00 75 00 6e 00 50 00 72 00 6f}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 00 65 00 00 00 00 00 48 00 65 00 6c 00 6c 00 6f 00 20 00 57 00 6f 00 72 00 6c 00 64 00 ae 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 00 72 00 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASB_2147891788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASB!MTB"
        threat_id = "2147891788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 31 d2 f7 f3 0f b6 44 15 00 30 04 0e 83 c1 01 39 cf 75}  //weight: 1, accuracy: High
        $x_1_2 = {89 34 24 89 44 24 04 c7 45 ?? 66 75 63 6b c7 45 ?? 79 6f 75 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Users\\Public\\dwwmm.txt" ascii //weight: 1
        $x_1_4 = "/m1.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GMP_2147892359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GMP!MTB"
        threat_id = "2147892359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 ?? b0 a5 00 89 35 ?? aa a5 00 8b fe 38 18}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 fc 83 c4 14 48 89 35 ?? aa a5 00 5f 5e a3 ?? a9 a5 00 5b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GMQ_2147892563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GMQ!MTB"
        threat_id = "2147892563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 04 01 00 00 56 53 ff 15 ?? ?? ?? ?? a1 ?? ?? a5 00 89 35 ?? 89 a5 00 8b fe 38 18 ?? ?? 8b f8 8d 45 f8 50 8d 45 fc 50}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 fc 83 c4 14 48 89 35 ?? 89 a5 00 5f 5e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASC_2147892784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASC!MTB"
        threat_id = "2147892784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 c8 c1 e1 10 0b f1 8b 55 f0 89 72 1c 8b 45 f0 8b 48 0c 8b 55 f0 03 4a 1c 8b 45 f0 89 48 0c 8b 4d f0 8b 51 14 33 55 ec 8b 45 f0 89 10}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 0c 52 6a 00 6a 01 6a 01 68 30 00 01 00 8b 45 08 50}  //weight: 1, accuracy: High
        $x_1_3 = "{A58F1A39-A340-11D9-BC6B-00A0C90312EA}-0x13579bdf_0x13579bdf" ascii //weight: 1
        $x_1_4 = "{71ED008B-67F9-439c-A3BD-4AEF76D95630}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASD_2147892877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASD!MTB"
        threat_id = "2147892877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d3 8d 92 3f bf 1f d3 3a c8 81 f2 6d 0d 93 35 f8 f7 d2 81 ea 42 3d ce 2b d1 ca f5 81 c2 2c 0e 24 31 e9}  //weight: 2, accuracy: High
        $x_2_2 = {57 65 42 a1 fa 09 f8 61 6c 39 ff 16 d6 68 f6 8f 40 58 f1 f8 e3 cd 95 66 75 fd 92 11 cf ac 9b 88 59 9c 9c ff c8 81 23 6f 5e b1 24 18 e4 e0 2d 81 72 d0 2a f6 d1 45 4e 68 47 75 49 1f fd 24 40}  //weight: 2, accuracy: High
        $x_1_3 = {40 03 00 00 2e 00 00 00 00 00 00 5e 16 2f 00 00 10 00 00 00 50 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_DA_2147893098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.DA!MTB"
        threat_id = "2147893098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7b 5c e9 eb 33 7a fa 5a 81 48 04 52 d8 49 c2 c9 83 d2 75 b2 a1 15 93 3d bb b9 af 25 b4 21 3b a5 53 11 be b5 26 2a 1b 6c 57 29 2f 25 3b 2e 16 85 2b 35 39 41 a3 fd 27 d5 4b b1 5f 21 3f b5 f1 28 db 31 33 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASF_2147893510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASF!MTB"
        threat_id = "2147893510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {50 68 01 03 00 80 6a 00 68 02 00 00 00 68 02 00 03 00 68 26 0e 01 16 68 01 00 01 52 68 03 00 00 00 b8 02 00 00 00 bb}  //weight: 2, accuracy: High
        $x_1_2 = "kljszdfyrweon34v9345,oireu" ascii //weight: 1
        $x_1_3 = "wsdlq.com/wg/wlbb.txt" ascii //weight: 1
        $x_1_4 = "|yanchicaozuo|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASE_2147893511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASE!MTB"
        threat_id = "2147893511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "{E5000198-4471-40e2-92BC-D0BA075BDBB2}" ascii //weight: 2
        $x_2_2 = "A888C6786F8845a99F6D0860A9EED608" ascii //weight: 2
        $x_2_3 = "Software\\xcy\\ml" ascii //weight: 2
        $x_2_4 = "xieyilei2001.ys168.com" ascii //weight: 2
        $x_2_5 = {83 c4 10 89 45 d8 68 01 01 00 80 6a 00 68 65 00 00 00 68 01 00 00 00 bb ?? ?? ?? 00 e8}  //weight: 2, accuracy: Low
        $x_1_6 = {e7 d7 c6 bd b2 ad a5 96 9c 52 3c 4a 4a 3c 42 42 41 39 4a 4d 42 73 79 84 6b 6d 29 e7 ba 42 f7 be 42 ff c7 39 ff c7 39 f7 c3 42 18 0c}  //weight: 1, accuracy: High
        $x_1_7 = {2c 52 31 30 6b ad ba c6 18 38 73 00 34 4a 31 5d 73 42 41 4a 00 30 7b 63 df f7}  //weight: 1, accuracy: High
        $x_1_8 = "51mole.com" ascii //weight: 1
        $x_1_9 = "mole.61.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_ASG_2147893843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASG!MTB"
        threat_id = "2147893843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2F8761CF148F88C2640DBBA783EF2917" ascii //weight: 1
        $x_1_2 = "wg148.com/newgo.html0" ascii //weight: 1
        $x_1_3 = "F2730835_2229_445E_97C7_l3F7612771DA" ascii //weight: 1
        $x_1_4 = "zy.anjian.com/soft/xjl/xjl.php" ascii //weight: 1
        $x_1_5 = "xunxunjp.com/1018jp.txt" ascii //weight: 1
        $x_1_6 = "6aa0b77d-452a-4727-a2c2-e03808227ea1" ascii //weight: 1
        $x_1_7 = "{E5000198-4471-40e2-92BC-D0BA075BDBB2}" ascii //weight: 1
        $x_1_8 = "63 6E 2F 71 6D 61 63 72 6F 2F 70 6C 75 67 69 6E 2E 68 74 6D" ascii //weight: 1
        $x_1_9 = "79 75 37 36 38 38 6B 73 6C 69 6F" ascii //weight: 1
        $x_1_10 = "fufzebtUVaIKTTS_]^[`]ornkyur" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMAB_2147893928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMAB!MTB"
        threat_id = "2147893928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 b4 c1 ea 05 29 f3 29 f7 29 d0 89 c2 8b 45 ac 40 66 89 11 3d}  //weight: 2, accuracy: High
        $x_2_2 = {8b 5d d0 8b 55 e8 01 da 8b 5d e8 89 4d e8 29 d8 89 cb 8b 4d d0 01 d9 8a 1c 02 42 88 5a ff 39 d1}  //weight: 2, accuracy: High
        $x_1_3 = "TianqiDream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASH_2147894048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASH!MTB"
        threat_id = "2147894048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /f /t /im iphoneqq.exe" ascii //weight: 2
        $x_1_2 = "iwofeng.com/tc.txt" ascii //weight: 1
        $x_1_3 = "E5 B8 90 E5 8F B7 E6 88 96 E5 AF 86 E7 A0 81 E9 94 99 E8 AF AF" ascii //weight: 1
        $x_1_4 = "E8 AF B7 E8 BE 93 E5 85 A5 E9 AA 8C E8 AF 81 E7" ascii //weight: 1
        $x_1_5 = "08 00 01 06 0F 52 65 71 47 65 74 42 6C 61 63 6B 4C 69 73 74 18 00 01" ascii //weight: 1
        $x_1_6 = "06 19 41 63 63 6F 73 74 53 76 63 2E 52 65 71 47 65 74 42 6C 61 63 6B 4C 69 73 74 1D 00" ascii //weight: 1
        $x_1_7 = "61 6E 5F 31 76 01 31 8C 0B 06 10 52 65 71 75 65" ascii //weight: 1
        $x_1_8 = "73 74 56 65 72 69 66 79 50 69 63 18 00 01 06 19" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBKL_2147894282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBKL!MTB"
        threat_id = "2147894282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 67 41 79 75 69 73 79 78 00 00 00 42 69 63 79 63 6c 65 20 77 61 74 65 72 00 00 00 64 53 2a 64 38 39 33 62 65 6a 64 73 61 64 63 73 77}  //weight: 1, accuracy: High
        $x_1_2 = {66 64 69 6f 67 69 75 41 73 64 6f 69 48 59 55 41 55 41 59 38 37 32 33 34 00 00 00 00 73 75 69 68 38 39 41 68 33 00 00 00 58 53 63 64 79 68 6a 6b 75 6a 6b 74 79 79 74 00 73 4a 42}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPA_2147894386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPA!MTB"
        threat_id = "2147894386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 36 ed ff ff 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0 5d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPA_2147894386_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPA!MTB"
        threat_id = "2147894386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 55 d0 03 55 f8 0f b6 02 83 f0 57 8b 4d e4 03 4d f8 88 01 eb 52 8b 45 f8 33 d2 b9 03 00 00 00 f7 f1 83 fa 01 75 16 8b 55 d0 03 55 f8 0f b6 02 83 f0 77 8b 4d e4 03 4d f8 88 01 eb 2b 8b 45 f8 33 d2 b9 03 00 00 00 f7 f1 83 fa 02 75 1a 8b 55 d0 03 55 f8 0f b6 02 83 f0 36 0f b6 4d f8 33 c1 8b 55 e4 03 55 f8 88 02 e9 72 ff ff ff}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GNS_2147894657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GNS!MTB"
        threat_id = "2147894657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 f7 89 f0 31 db 83 c7 58 81 2e ?? ?? ?? ?? 83 c6 04 66 ba ?? ?? 39 fe 7c ?? 66 be ?? ?? bb ?? ?? ?? ?? 53 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GNS_2147894657_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GNS!MTB"
        threat_id = "2147894657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 f3 8d 41 f8 01 55 fc 33 d2 f7 f3 8b c1 03 f2 33 d2 f7 f3 8d 41 08 83 c1 20 03 fa 33 d2 f7 f3 01 55 f8 ff 4d f4 ?? ?? 8b 45 f8 8b 4d f0 03 c7 03 c6 01 45 fc 83 c1 65 89 4d f0 81 f9 10 50 06 00}  //weight: 10, accuracy: Low
        $x_1_2 = "cmd.exe /c net user hello123 hellxxx_Hxxx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPAB_2147895179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPAB!MTB"
        threat_id = "2147895179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b c2 99 8b f8 8b c6 33 fa 2b fa 8b 94 24 ?? 00 00 00 2b c2 99 33 c2 2b c2 3b f8 7e 2f 8b 44 24 ?? 8b d0 2b d1 8b 8c 24 ?? ?? 00 00 2b c8 0f af d1 85 d2 7e 0d 8b 94 24 ?? ?? ?? 00 89 54 24}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_DIW_2147895372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.DIW!MTB"
        threat_id = "2147895372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 d5 8b c8 c1 e1 04 89 54 24 1c 03 cb 8d 14 06 33 ca 89 4c 24 10 89 3d ?? ?? ?? ?? 8b 44 24 1c 01 05 a4 87 7b 00 a1 ?? ?? ?? ?? 89 44 24 34 89 7c 24 1c 8b 44 24 34 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPAF_2147895502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPAF!MTB"
        threat_id = "2147895502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 c6 83 fe 07 0f 45 c8 0f b6 01 b9 01 00 00 00 30 84 3d ?? ?? ?? ?? 83 fe 07 8d 46 02 0f 45 c8 33 d2 83 f9 08}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBEO_2147895515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBEO!MTB"
        threat_id = "2147895515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Disipuro kobumajeruluxe pakufohur tudelijigapo kajopoketidago duxemumute hafu buhibiyocabejo" wide //weight: 1
        $x_1_2 = "Sadulimuceg tecamosuzicihi soja jom wacev dam dos" wide //weight: 1
        $x_1_3 = "Velunocom judahi zadidalojire dahasinojo migoxilezec luci fenokugugu" wide //weight: 1
        $x_1_4 = "Lufut kufir xodiwono hivisifama" wide //weight: 1
        $x_1_5 = "Sefocej nawi ham xulekafahukede diyapulalocos jofagobezanog kanixowisosazar sunivosoriwa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASI_2147895627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASI!MTB"
        threat_id = "2147895627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "112.175.69.77 pk555.com 777wt.com www.777wt.com 79.sf923.com sf777.com www.sf99.cc sf99.cc www.meishipai.com jdmzd.com" ascii //weight: 2
        $x_2_2 = "67.198.179.75 www.22cq.com www.3000okhaosf.com hao119.haole56.com www.sf63.com 456ok.45195.com 79.sf923.com www.53uc.com 53uc.com www.recairen.com" ascii //weight: 2
        $x_1_3 = "Program Files\\xcdlq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASJ_2147895833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASJ!MTB"
        threat_id = "2147895833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Program Files\\xcdlq" ascii //weight: 1
        $x_1_2 = "Windows\\diskpt.dat" ascii //weight: 1
        $x_1_3 = "hash=d55d1b48c32efce16bb8a027efdr56a2" ascii //weight: 1
        $x_1_4 = "sn=24GAW-78SFC-DSPEG-E31U3-Z3TD7" ascii //weight: 1
        $x_1_5 = {65 61 d4 a3 59 72 6e 6a 66 62 5e 59 5a 77 73 6f 6b 67 63 5f 59 5b 78 74 70 6c 68 64 60 59 5c ec dc f0 e0 f4 e4 f8 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASJ_2147895833_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASJ!MTB"
        threat_id = "2147895833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BEA5AD199E201DABBDE32269C6B690CF" ascii //weight: 1
        $x_1_2 = "wallet.tenpay.com/cgi-bin/v1.0/queryqb.cgi" ascii //weight: 1
        $x_1_3 = "E5 B8 90 E5 8F B7 E6 88 96 E5 AF 86 E7 A0 81 E9 94 99 E8 AF AF" ascii //weight: 1
        $x_1_4 = "10 01 2C 36 00 40 0B 50 01 60 01 70 01 8C 9C AC BC C0 01" ascii //weight: 1
        $x_1_5 = "08 00 01 06 0F 52 65 71 47 65 74 42 6C 61 63 6B 4C 69 73 74 18 00 01" ascii //weight: 1
        $x_1_6 = "06 19 41 63 63 6F 73 74 53 76 63 2E 52 65 71 47 65 74 42 6C 61 63 6B 4C 69 73 74 1D 00" ascii //weight: 1
        $x_1_7 = "1C 2C 36 00 40 15 5C 60 01 70 01 8C 9C A1 02 5E" ascii //weight: 1
        $x_1_8 = "74 4F 62 6A 66 11 43 4D 44 5F 47 45 54 5F 42 6C" ascii //weight: 1
        $x_1_9 = "iwofeng.com/tc.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_DV_2147896047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.DV!MTB"
        threat_id = "2147896047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s:%d/%s/%s" ascii //weight: 1
        $x_1_2 = "%s%.8x.bat" ascii //weight: 1
        $x_1_3 = "if exist \"%s\" goto :DELFILE" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\GTplus" ascii //weight: 1
        $x_1_5 = "%s M %s -r -o+ -ep1 \"%s\" \"%s\\*\"" ascii //weight: 1
        $x_1_6 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_7 = "ShellExecuteA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GCI_2147896112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GCI!MTB"
        threat_id = "2147896112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c0 b1 61 eb ?? 8d a4 24 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 40 3d bc 02 00 00 72}  //weight: 10, accuracy: Low
        $x_10_2 = {72 88 5c 24 ?? c6 44 24 ?? 61 c6 44 24 ?? 74 88 5c 24 ?? c6 44 24 ?? 74 88 44 24 ?? c6 44 24 ?? 54 c6 44 24 ?? 68 c6 44 24 ?? 72 88 5c 24 ?? c6 44 24 ?? 61 c6 44 24 ?? 64 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GND_2147896159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GND!MTB"
        threat_id = "2147896159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {9c 2d 45 00 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 02 2e 45 00 c7 05 ?? ?? ?? ?? 42 2d 45 00 c7 05 ?? ?? ?? ?? ea 2d 45 00}  //weight: 10, accuracy: Low
        $x_10_2 = {fc 29 45 00 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 62 2a 45 00 c7 05 ?? ?? ?? ?? a2 29 45 00 c7 05 ?? ?? ?? ?? 4a 2a 45 00}  //weight: 10, accuracy: Low
        $x_1_3 = "voipcall.taobao" ascii //weight: 1
        $x_1_4 = "qsyou.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_AMBA_2147896311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMBA!MTB"
        threat_id = "2147896311"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 4b 80 61 4b 80 e4 af f3 9a a5 e4 9c 83 be 8c 43 80 b1 97 c4 49 a6 ac a6 e4 e4 af f3 9a a5 e4 9c 83 be 8c 43 80 b1 97 c4 49 a6 ac a6 e4}  //weight: 1, accuracy: High
        $x_1_2 = {1b 11 00 fb 30 1c 08 02 27 04 ff 27 3c ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RDD_2147896682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RDD!MTB"
        threat_id = "2147896682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 1f 8b 55 ec 8b 5d d4 32 0c 1a 8b 55 e8 88 0c 1a 81 c3 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASK_2147896721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASK!MTB"
        threat_id = "2147896721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "43.136.234.140:7890/Cloud150/SSDTHook_IO_Link.txt" ascii //weight: 2
        $x_1_2 = "AQAQAQ.txt" ascii //weight: 1
        $x_1_3 = "ktkt.txt" ascii //weight: 1
        $x_1_4 = "CMD /C SC DELETE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_ASK_2147896721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASK!MTB"
        threat_id = "2147896721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "82709784547583932748352793275748" ascii //weight: 1
        $x_1_2 = "DhhiggUlqsacaBnlokaT" ascii //weight: 1
        $x_1_3 = "Zzv|eiHodfpkbvako" ascii //weight: 1
        $x_1_4 = "UteNpt2HgazewrUmZvtjloS" ascii //weight: 1
        $x_1_5 = "KrmuhahnUfa|mnlFgmZwmmEfwot" ascii //weight: 1
        $x_2_6 = {c2 01 c6 41 4f 00 44 88 41 5c eb 75 41 b0 01 41 02 d0 88 51 64 3a 51 5a 73 7a 0f b6 c2 46 8a 0c 08 41 80 f9 38 75 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ARA_2147896826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ARA!MTB"
        threat_id = "2147896826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0f 8a c1 32 c4 8a e1 88 07 47 43 3b de 72 f0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ARA_2147896826_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ARA!MTB"
        threat_id = "2147896826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 31 d2 f7 f6 8b 47 28 0f b6 04 10 30 04 0b 83 c1 01 39 cd 75 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ARA_2147896826_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ARA!MTB"
        threat_id = "2147896826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 81 80 80 80 f7 e1 c1 ea 07 02 d1 30 91 ?? ?? ?? ?? 41 81 f9 eb d5 06 00 72 e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ARA_2147896826_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ARA!MTB"
        threat_id = "2147896826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 56 57 6a 40 bf 50 c6 04 00 68 00 30 00 00 33 db 57 53 ff 15 10 10 40 00}  //weight: 2, accuracy: High
        $x_2_2 = {53 53 56 56 53 53 ff 15 14 10 40 00}  //weight: 2, accuracy: High
        $x_2_3 = {6a ff 50 ff 15 18 10 40 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ARA_2147896826_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ARA!MTB"
        threat_id = "2147896826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 d1 41 81 e1 ff 00 00 80 88 94 05 60 fd ff ff 79 08 49 81 c9 00 ff ff ff 41 40 83 f8 ?? 7c da}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 84 0f 74 24 a6 b2 32 c2 42 81 e2 ff 00 00 80 88 04 31 79 08 4a 81 ca 00 ff ff ff 42 41 83 f9 0e 7c dd}  //weight: 2, accuracy: High
        $x_1_3 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_ASL_2147896923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASL!MTB"
        threat_id = "2147896923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "Global\\{2BF0F328-0B44-4325-9452-16FC8058D2E8}" wide //weight: 4
        $x_4_2 = "Global\\74CD674D-FBFA-462B-B4CD-8762469B19ECAdbkTray" wide //weight: 4
        $x_1_3 = {77 00 6f 00 72 00 6b 00 73 00 70 00 61 00 63 00 65 00 5c 00 [0-48] 5c 00 62 00 69 00 6e 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 41 00 44 00 42 00 6c 00 6f 00 63 00 6b 00 4d 00 61 00 73 00 74 00 65 00 72 00 54 00 72 00 61 00 79 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_4 = {77 6f 72 6b 73 70 61 63 65 5c [0-48] 5c 62 69 6e 5c 52 65 6c 65 61 73 65 5c 41 44 42 6c 6f 63 6b 4d 61 73 74 65 72 54 72 61 79 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_GMA_2147897195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GMA!MTB"
        threat_id = "2147897195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {36 82 4d 00 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 9c 82 4d 00 c7 05 ?? ?? ?? ?? dc 81 4d 00 c7 05 ?? ?? ?? ?? 84 82 4d 00 a3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMBE_2147897335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMBE!MTB"
        threat_id = "2147897335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c0 c8 03 32 83 ?? ?? ?? ?? 6a 0d 88 81 ?? ?? ?? ?? 8d 43 01 99 5b f7 fb 41 8b da 3b ce 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GAD_2147898845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GAD!MTB"
        threat_id = "2147898845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3a 42 01 c6 81 ee ?? ?? ?? ?? 39 da 75 ?? 81 e8 ?? ?? ?? ?? c3 48 09 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZA_2147898942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZA!MTB"
        threat_id = "2147898942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 85 cc ff ff ff ?? ?? ?? ?? 8b 3e c7 85 f0 ff ff ff ?? ?? ?? ?? 33 fb 81 85 dc ff ff ff ?? ?? ?? ?? 89 3a 29 95 fc ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "WY*DU[P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZA_2147898942_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZA!MTB"
        threat_id = "2147898942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 57 75 05 e8 0c fb ff ff 8b 35 ?? ?? ?? ?? 33 ff 8a 06 3a c3 74 12}  //weight: 5, accuracy: Low
        $x_5_2 = {e8 3c dd ff ff 59 8d 74 06 ?? eb e8 8d 04 bd ?? ?? ?? ?? 50 e8 6f cb ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZU_2147898966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZU!MTB"
        threat_id = "2147898966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c2 c1 e8 18 89 4e 06 0f b6 0c 85 20 5d 5f 00 0f b6 46 0b 8b 0c 8d 20 51 5f 00 0f b6 04 85 20 5d 5f 00 33 0c 85 20 49 5f 00 0f b6 46 0c 0f b6 04 85 20 5d 5f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZU_2147898966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZU!MTB"
        threat_id = "2147898966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 e9 02 f3 a5 8b ca 83 e1 03 68 98 64 41 00 f3 a4 50 e8 ?? ?? ?? ?? 8b f0 8d 85 8c fe ff ff 56 6a 64 6a 01 50}  //weight: 2, accuracy: Low
        $x_1_2 = {8a 47 01 8d 7f 01 84 c0 75 f6 a1 ?? ?? ?? ?? 89 07 8d 45 8c 6a 00 50 ff 15 ?? ?? ?? ?? 8b 4d fc 5f 33 cd 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZU_2147898966_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZU!MTB"
        threat_id = "2147898966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 cc 43 c6 45 cd 3a c6 45 ce 5c c6 45 cf 55 c6 45 d0 73 c6 45 d1 65 c6 45 d2 72 c6 45 d3 73 c6 45 d4 5c c6 45 d5 50 c6 45 d6 75 c6 45 d7 62 c6 45 d8 6c c6 45 d9 69 c6 45 da 63 c6 45 db 5c c6 45 dc 43 c6 45 dd 6f c6 45 de 4e c6 45 df 6e c6 45 e0 55 c6 45 e1 6f c6 45 e2 62 c6 45 e3 64 c6 45 e4 73 c6 45 e5 5c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZU_2147898966_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZU!MTB"
        threat_id = "2147898966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 c4 c6 45 dc 4b c6 45 dd 45 c6 45 de 52 c6 45 df 4e c6 45 e0 45 c6 45 e1 4c c6 45 e2 33 c6 45 e3 32 c6 45 e4 2e c6 45 e5 64 c6 45 e6 6c c6 45 e7 6c 88 5d e8 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 cc 47 c6 45 cd 65 c6 45 ce 74 c6 45 cf 50 c6 45 d0 72 c6 45 d1 6f c6 45 d2 63 c6 45 d3 65 c6 45 d4 73 c6 45 d5 73 c6 45 d6 48 c6 45 d7 65 c6 45 d8 61 c6 45 d9 70 88 5d da ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZY_2147899007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZY!MTB"
        threat_id = "2147899007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8a 81 a8 7c 42 00 30 04 0a 83 e9 01}  //weight: 3, accuracy: High
        $x_2_2 = {8a 8d c1 42 ff ff 32 8d c0 42 ff ff 80 c9 50 30 c1 88 8c 15 c0 42 ff ff 42}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZY_2147899007_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZY!MTB"
        threat_id = "2147899007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c2 47 c1 e8 18 0f b6 0c 85 f0 bc 5e 00 0f b6 46 ff 8b 0c 8d f0 b0 5e 00 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 a8 5e 00 0f b6 c2 8b 56 02 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 a4 5e 00 0f b6 06 0f b6 04 85 f0 bc 5e 00 33 0c 85 f0 ac 5e 00 8b c2 c1 e8 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZY_2147899007_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZY!MTB"
        threat_id = "2147899007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {bf 02 9f f5 24 bb 16 27 1a 3f bd 2c 25 34 b6 8b 4c 24 24 81 f9 01 9f f5 24 7f 61 81 f9 6a d2 00 e1 0f 8e a7 00 00 00 81 f9 1d 08 72 f8 0f 8f 42 01 00 00 81 f9 6b d2 00 e1 0f 84 0a 02 00 00 81 f9 1f 1f dd e5 0f 84 3d 02 00 00 81 f9 38 08 97 f5}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4c 24 14 8a 54 24 0b 80 c2 34 88 54 01 30 8b 4c 24 14 8a 54 24 0b 80 c2 35 88 54 01 31 8b 0c 24 c7 01 1f 1f dd e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZY_2147899007_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZY!MTB"
        threat_id = "2147899007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 46 08 89 45 cc 8d 95 68 fe ff ff b8 64 89 4b 00 e8 2f f5 ff ff 8b 95 68 fe ff ff 8b 45 c4 e8 0d c3 f4 ff 75 02 b3 01 8d 95 64 fe ff ff b8 88 89 4b 00 e8 0d f5 ff ff 8b 95 64 fe ff ff 8b 45 c4 e8 eb c2 f4 ff 75 04 c6 45 fb 01 8d 95 60 fe ff ff b8 a4 89 4b 00 e8 e9 f4 ff ff 8b 95 60 fe ff ff 8b 45 c4 e8 c7 c2 f4 ff 75 04 c6 45 fa 01 8d 95 5c fe ff ff b8 c8 89 4b 00}  //weight: 2, accuracy: High
        $x_1_2 = "019F9A277A51DE285787CF3C77" ascii //weight: 1
        $x_1_3 = "54C0D821744CC96B57D1CF" ascii //weight: 1
        $x_1_4 = "51C1D82B7F469F204ACC" ascii //weight: 1
        $x_1_5 = "50C8C3206741C32A45DACF363C46C920" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZS_2147899084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZS!MTB"
        threat_id = "2147899084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 56 0e 8d 76 10 8b c2 47 c1 e8 18 0f b6 0c 85 70 5c 5f 00 0f b6 46 ff 8b 0c 8d 70 50 5f 00 0f b6 04 85 70 5c 5f 00 33 0c 85 70 48 5f 00 0f b6 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZS_2147899084_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZS!MTB"
        threat_id = "2147899084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 ca c1 ea 08 33 34 8d c0 6a 47 00 0f b6 d2 8b ce 33 48 18 8b 14 95 c0 6e 47 00 89 75 f8 89 4d f8 8b 4d e4 c1 e9 10 0f b6 c9 33 14 8d c0 72 47 00 8b 4d ec c1 e9 18 33 14 8d c0 76 47 00 0f b6 cb 33 14 8d c0 6a 47 00}  //weight: 2, accuracy: High
        $x_1_2 = {8b cb 33 50 10 c1 e9 10 89 55 f0 0f b6 d1 8b 4d ec 8b 14 95 c0 72 47 00 c1 e9 08 0f b6 c9 33 14 8d c0 6e 47 00 8b 4d dc c1 e9 18 33 14 8d c0 76 47 00 89 55 fc 8b 55 e4 8b 7d fc 0f b6 ca 33 3c 8d c0 6a 47 00 8b cf 33 48 14 89 7d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZS_2147899084_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZS!MTB"
        threat_id = "2147899084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 60 60 24 10 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d}  //weight: 2, accuracy: High
        $x_1_2 = {c6 85 06 ff ff ff 52 c6 85 07 ff ff ff 68 c6 85 08 ff ff ff 63 c6 85 09 ff ff ff 32 c6 85 0a ff ff ff 74 c6 85 0b ff ff ff 4f c6 85 0c ff ff ff 59 c6 85 0d ff ff ff 57 c6 85 0e ff ff ff 31 c6 85 0f ff ff ff 6c c6 85 10 ff ff ff 49 c6 85 11 ff ff ff 43 c6 85 12 ff ff ff 52 c6 85 13 ff ff ff 30 c6 85 14 ff ff ff 59 c6 85 15 ff ff ff 58 c6 85 16 ff ff ff 4e c6 85 17 ff ff ff 72 c6 85 18 ff ff ff 54 c6 85 19 ff ff ff 6d c6 85 1a ff ff ff 46 c6 85 1b ff ff ff 74 c6 85 1c ff ff ff 5a c6 85 1d ff ff ff 51 c6 85 1e ff ff ff 3d c6 85 1f ff ff ff 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GAF_2147899455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GAF!MTB"
        threat_id = "2147899455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 07 80 f1 49 8a 4f 04 e9 ?? ?? ?? ?? 0c f1 80 24 23 9f 4c}  //weight: 10, accuracy: Low
        $x_10_2 = {31 d1 13 fc 2a cf 96}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SA_2147899923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SA!MTB"
        threat_id = "2147899923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c6 8d 5b ?? 33 c7 69 f8 ?? ?? ?? ?? 8b c7 c1 e8 ?? 33 f8 0f b7 03 8b f0 66 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPXR_2147899963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPXR!MTB"
        threat_id = "2147899963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0e 30 08 8a 08 8a 16 02 d1 88 10 40 46 4f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMBG_2147899980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMBG!MTB"
        threat_id = "2147899980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0e 30 08 8a 08 8a 16 02 d1 88 10 40 46 4f 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GAN_2147900137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GAN!MTB"
        threat_id = "2147900137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4e 09 c2 c3 31 06 81 c6 04 00 00 00 29 d2 39 de}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASU_2147900814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASU!MTB"
        threat_id = "2147900814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "replenish.p8Nighta" wide //weight: 1
        $x_1_2 = "greatthingisundergivesea.Pin.Pdays" wide //weight: 1
        $x_1_3 = "BroughtshallWhalesL" wide //weight: 1
        $x_1_4 = "isn.tafifthgrass.dMafter,4" wide //weight: 1
        $x_1_5 = "Beastrgodwon.tand2fly" wide //weight: 1
        $x_1_6 = "Phadgood.MdivideWxflysx" ascii //weight: 1
        $x_1_7 = "togetherfowlappear5yearsthe3saying.o6" ascii //weight: 1
        $x_1_8 = "heavenmeatbeholdyou.rejseed" ascii //weight: 1
        $x_1_9 = "bcalledthey.retmayflyIY0r" ascii //weight: 1
        $x_1_10 = "thatourGreater.Bhad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Zusy_DE_2147901236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.DE!MTB"
        threat_id = "2147901236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c6 83 f0 0a b9 e0 00 00 00 99 f7 f9 8b ca}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 33 db 8a 5c 30 ff 2b d9 83 eb 20 83 fb 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPX_2147902709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPX!MTB"
        threat_id = "2147902709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 62 0a 00 3c 87 da e7 c8 fd}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASFC_2147903393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASFC!MTB"
        threat_id = "2147903393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {43 72 65 61 74 65 41 75 64 69 6f 44 65 63 6f 64 65 72 00 43 72 65 61 74 65 56 69 64 65 6f 44 65 63 6f 64 65 72 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 45 6e 74 72 79}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PTJH_2147903588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PTJH!MTB"
        threat_id = "2147903588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 bb 00 00 00 00 01 d3 31 03 5b 5a 68 46 fd 6d 1c 89 04 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ASFO_2147905228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ASFO!MTB"
        threat_id = "2147905228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 6a 40 68 00 30 00 00 68 a0 07 00 00 6a 00 56 ff 15 ?? ?? ?? ?? 8b f8 85 ff}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c4 0c 8d 85 f0 fd ff ff 50 8d 85 f4 fd ff ff 50 ff 15 ?? ?? ?? ?? 8d 85 f4 fd ff ff 50 6a 00 6a 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNA_2147907440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNA!MTB"
        threat_id = "2147907440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 6a 02 6a 00 6a 00 6a 03 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 6a 00 6a 03 6a 00 6a 00 6a 01 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 50 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GZX_2147907549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GZX!MTB"
        threat_id = "2147907549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f6 dd 45 32 cd 46 89 14 2c 44 0f a3 d6 41 8b 34 24}  //weight: 5, accuracy: High
        $x_5_2 = {c0 e3 0d 00 0f 84 3f e4 02 00 8a d9 80}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMMH_2147908254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMMH!MTB"
        threat_id = "2147908254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNB_2147908515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNB!MTB"
        threat_id = "2147908515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 31 00 32 00 31 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 20 00 53 00 61 00 66 00 61 00 72 00 69 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 25 00 74 00 65 00 6d 00 70 00 25 [0-5] 25 00 73 00 5c 00 25 00 64 00 25 00 64 00 2e 00 65 00 78 00 65 00 00 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = "23t43f4ft23f423t43f4ft23f423t43f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_GXZ_2147908979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GXZ!MTB"
        threat_id = "2147908979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "retliften\\secivreS\\teSlortnoCtnerruC\\METSYSs" ascii //weight: 1
        $x_1_2 = "niamoDnigoL" ascii //weight: 1
        $x_1_3 = "epytyalpsiDecruoseR" ascii //weight: 1
        $x_1_4 = "epyTsserddArellortnoCniamoD" ascii //weight: 1
        $x_1_5 = "stopify.co/news.php?tid=JBB69H.jpg" ascii //weight: 1
        $x_1_6 = "\\AppData\\Local\\Temp\\bin.exe" ascii //weight: 1
        $x_1_7 = "/tsoHbrKdetcirtseR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPCT_2147911075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPCT!MTB"
        threat_id = "2147911075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 20 8d 4c 24 34 8a 44 04 68 30 07 e8 ?? ?? ?? ?? 8b 5c 24 24 47 8b 54 24 28 81 ff}  //weight: 2, accuracy: Low
        $x_1_2 = {0f b6 44 1c ?? 03 c6 33 ed 0f b6 c0 59 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GXB_2147911775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GXB!MTB"
        threat_id = "2147911775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 8a 84 35 ?? ?? ?? ?? 88 8c 35 ?? ?? ?? ?? 0f b6 c8 88 84 3d ?? ?? ?? ?? 0f b6 84 35 ?? ?? ?? ?? 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 32 44 1a 08 88 04 11 42 81 fa 00 30 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RW_2147911820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RW!MTB"
        threat_id = "2147911820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 72 cb bd 9e 9f 6f 59 ec 4e 18 f3 94 ee}  //weight: 1, accuracy: High
        $x_1_2 = {f1 8c 00 be 7b d7 4c 4e 31 63 58 22 74 db 35 3d af 7c 0b da dd 1e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RZ_2147913104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RZ!MTB"
        threat_id = "2147913104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 64 f4 ff ff 8a 08 88 8d 77 f4 ff ff 8b 95 68 f4 ff ff 8a 85 77 f4 ff ff 88 02 8b 8d 64 f4 ff ff 83 c1 01}  //weight: 1, accuracy: High
        $x_1_2 = "pipe\\vSDsGRFs62ghf" ascii //weight: 1
        $x_1_3 = "pipe\\vsVSDDTGHGSy54" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ZX_2147913992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ZX!MTB"
        threat_id = "2147913992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 e8 03 55 dc 0f b6 02 8b 4d e8 03 4d dc 0f b6 51 ff 33 c2 8b 4d e8 03 4d dc 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMAI_2147914073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMAI!MTB"
        threat_id = "2147914073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 30 04 39 8b c2 8b 4c 24 ?? 2b ca 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPSS_2147914507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPSS!MTB"
        threat_id = "2147914507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "jmweczbxcvjsi" ascii //weight: 2
        $x_2_2 = "migjtsuukjvt" ascii //weight: 2
        $x_2_3 = "pzvmkcouyvqk" ascii //weight: 2
        $x_2_4 = "vyhbiozzrw" ascii //weight: 2
        $x_1_5 = "zjjcrmbehoakm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MZZ_2147914571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MZZ!MTB"
        threat_id = "2147914571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 0f b6 84 34 28 01 00 00 88 84 1c 28 01 00 00 88 8c 34 28 01 00 00 0f b6 84 1c 28 01 00 00 8b 4c 24 1c 03 c2 0f b6 c0 89 74 24 18 0f b6 84 04 ?? ?? ?? ?? 30 04 39 47 3b 7d 0c 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMMI_2147915078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMMI!MTB"
        threat_id = "2147915078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be c3 07 79 b1 b1 ad 6e 83 8c b0 69 8c 9d 83 d2 ce 8c 7e 7e 50 ad 9f c8 83 69 7c b0 b1 50 b1 b1 d2 ce ad 9a 8c 69 89 c5 83 8c b0 79 6e d2 c7 69}  //weight: 1, accuracy: High
        $x_1_2 = {6a 40 68 00 10 00 00 68 ac 04 00 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SHZC_2147916917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SHZC!MTB"
        threat_id = "2147916917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 45 f9 8a 45 f9 0f b6 c8 0f b6 15 ?? ?? ?? ?? 31 d1 88 cc 88 25 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? e8 15 00 00 c7 05 ?? ?? ?? ?? f1 18 00 00 0f b6 05 ?? ?? ?? ?? 83 c4 04 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SHZC_2147916917_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SHZC!MTB"
        threat_id = "2147916917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 30 c8 89 f7 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBXO_2147917978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBXO!MTB"
        threat_id = "2147917978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 19 4c 00 68 ?? aa 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? ?? ?? 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HND_2147918397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HND!MTB"
        threat_id = "2147918397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 0c 0a 30 08 e8 ?? ?? ?? ?? 8b d0 8d 4d}  //weight: 5, accuracy: Low
        $x_5_2 = {23 a3 00 66 5f 28 04 66 c2 27 04 66 63 dc 0e 66 87 a7 0f 66 f7 14 11 66 62 66 05 66 65 44 01 66}  //weight: 5, accuracy: High
        $x_5_3 = {08 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 02 00 00 00 30 00 00 00 08 00 00 00 54 00 45 00 4d 00 50 00 00 00 00 00 08 00 00 00 2e 00 ?? 00 ?? 00 ?? 00 00 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Zusy_CCJL_2147919258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CCJL!MTB"
        threat_id = "2147919258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Global\\3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6" ascii //weight: 5
        $x_5_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBXT_2147920463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBXT!MTB"
        threat_id = "2147920463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 17 4c 00 68 ?? b5 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 12 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_WMAA_2147920972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.WMAA!MTB"
        threat_id = "2147920972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? d4 65 00 68 ?? 63 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 5d a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d a6 00 c1 e1 08 03 ca 89 0d ?? 5d a6 00 c1 e8 10 a3 ?? 5d a6 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBXU_2147921076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBXU!MTB"
        threat_id = "2147921076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e3 4b 00 68 ?? 8e 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e2 4b 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBXW_2147921639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBXW!MTB"
        threat_id = "2147921639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 86 46 00 68 ?? 35 46 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 82 46 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_XEAA_2147921699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.XEAA!MTB"
        threat_id = "2147921699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? eb 65 00 68 ?? 87 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 8a a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8a a6 00 c1 e1 08 03 ca 89 0d ?? 8a a6 00 c1 e8 10 a3 ?? 8a a6 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CCJK_2147921776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CCJK!MTB"
        threat_id = "2147921776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 f8 d4 65 00 68 08 64 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 a0 d2 65 00 33 d2 8a d4 89 15 ac 5d a6 00 8b c8 81 e1 ff 00 00 00 89 0d a8 5d a6 00 c1 e1 08 03 ca 89 0d a4 5d a6 00 c1 e8 10 a3 a0 5d a6 00 6a 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNM_2147921837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNM!MTB"
        threat_id = "2147921837"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {2e 6c 6e 6b 00 [0-4] 6e 6b 00 [0-8] [0-34] 00 00 ?? 14 00 00 ?? 03 03 03 [0-16] 03 03 03 03 03}  //weight: 6, accuracy: Low
        $x_6_2 = {60 2e 67 2e 62 2e 67 2e 64 2e 65 2e 60 2e 67 2e 63 2e 3b 2e 38 2e 00 70 00 00 fc 73 00 00 [0-16] 2e 6c 6e 6b 00}  //weight: 6, accuracy: Low
        $x_1_3 = "$IM3YYFM.au3" ascii //weight: 1
        $x_1_4 = {2e 61 75 33 00 00 de 01 43 3a 5c 24 52 65 63 79 63 6c 65 2e}  //weight: 1, accuracy: High
        $x_1_5 = {00 00 30 34 20 2d 20 44 6f 77 6e 6c 6f 61 64 73 2e 6c 6e 6b 00 6c 6e 6b 00 00 ?? ?? 0f 01 01}  //weight: 1, accuracy: Low
        $x_1_6 = {2e 70 73 31 00 70 73 31 00}  //weight: 1, accuracy: High
        $x_1_7 = {2e 6c 6e 6b 00 6b 00 00 6c 6e 6b}  //weight: 1, accuracy: High
        $x_1_8 = {2e 70 73 31 00 31 00 31 00 67 65 2e 70 73 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            ((2 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_HNN_2147921838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNN!MTB"
        threat_id = "2147921838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d9 8b c7 8d 8d ?? ?? ?? ?? 99 03 cf f7 fe 47 8a 82 ?? ?? ?? ?? 32 04 0b 88 01}  //weight: 2, accuracy: Low
        $x_1_2 = {c1 f9 04 c0 e0 02 0a c8 88 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBXY_2147922935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBXY!MTB"
        threat_id = "2147922935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6e 69 00 72 69 6f 74 63 6c 69 65 6e 74 3a 2f 2f 52 69 6f 74 43 6c 69 65 6e 74 53 65 72 76 69 63 65 73 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GPB_2147924198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GPB!MTB"
        threat_id = "2147924198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 7d 5f 00 d4 75 5f 00 98 7d 5f 00 bc 7d 5f 00 20 7d 5f 00 48 7d 5f 00 88 7d 5f 00 aa 7d 5f 00 cc 7d 5f 00 74 7d 5f 00 36 7d 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NS_2147924816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NS!MTB"
        threat_id = "2147924816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "yahhelper.no-ip.org" ascii //weight: 2
        $x_1_2 = "INFECTION PATH" ascii //weight: 1
        $x_1_3 = "IP=%s ComputerName=%s UserName=%s Attacked=%d/%d/%d" ascii //weight: 1
        $x_1_4 = "LAST KEY STROKE" ascii //weight: 1
        $x_1_5 = "LAST TOKEN INFO" ascii //weight: 1
        $x_1_6 = "capCreateCaptureWindowA" ascii //weight: 1
        $x_1_7 = "TheComputerOfTheGhost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNC_2147925659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNC!MTB"
        threat_id = "2147925659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {9c 60 55 8b ec 48 58 53 4f 5f 4f 3f b8 02 00 00 01 61 9d}  //weight: 2, accuracy: High
        $x_1_2 = {60 55 8b ec 53 33 db 57 68 01 80 00 00 53 6a 08 53 68 60 01 00 00 50 53 68 80 ec 41 00 68 80 91 40 00 68 c0 2e 42 00 50 53 81 c4 38 00 00 00 c9 61 9d}  //weight: 1, accuracy: High
        $x_3_3 = {68 01 80 00 00 25 ff ff ff bf 66 3d 06 00 81 c4 0c 00 00 00 c9 61 9d}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_GA_2147925881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GA!MTB"
        threat_id = "2147925881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winmgmts:\\.\\root\\cimv2" wide //weight: 1
        $x_1_2 = "WindDbg" wide //weight: 1
        $x_1_3 = "CryptDeriveKey" wide //weight: 1
        $x_1_4 = "GetTickCount" wide //weight: 1
        $x_1_5 = "DqlqlqFquqnqcqtqiqoqnqCqaqlqlq" wide //weight: 1
        $x_6_6 = "acvm7qw909e.exe" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_E_2147926605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.E!MTB"
        threat_id = "2147926605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b c1 88 04 14 42 0f be d2 83 fa 4d 7c e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_YAA_2147926652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.YAA!MTB"
        threat_id = "2147926652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 02 3b 42 cc 75 ?? 8b 84 24 ?? ?? ?? ?? 0f af 84 24 ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? 2b d0 33 da}  //weight: 4, accuracy: Low
        $x_1_2 = {8a 00 8b 8c 24 54 03 00 00 34 9a 89 8c 24 08 03 00 00 04 69 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBWB_2147926784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBWB!MTB"
        threat_id = "2147926784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 09 4c 00 68 ?? a8 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 03 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MZ_2147926866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MZ!MTB"
        threat_id = "2147926866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%userappdata%\\RestartApp.exe" ascii //weight: 2
        $x_2_2 = "bmqazzxl" ascii //weight: 2
        $x_2_3 = "defOff.exe" ascii //weight: 2
        $x_1_4 = "sxeuusit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GTN_2147927160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GTN!MTB"
        threat_id = "2147927160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 41 00 47 44 49 33 32 2e 64 6c 6c 00 00 00 42 ?? 74 ?? 6c 74 ?? 57 53 32 ?? 33 32 2e 64 6c 6c 00 64 33 ?? 39 2e 64 6c 6c 00 00 00 44 69 ?? 65 63 74 33 ?? 43}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_RDH_2147927236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.RDH!MTB"
        threat_id = "2147927236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 18 83 c0 46 89 44 24 10 90 83 6c 24 10 46 8a 44 24 10 30 04 32 83 bc 24 28 0c 00 00 0f 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CCJR_2147927757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CCJR!MTB"
        threat_id = "2147927757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 e4 65 c6 45 e5 72 c6 45 e6 72 c6 45 e7 6f c6 45 e8 72 c6 45 e9 3a c6 45 ea 30 c6 45 eb 78 c6 45 ec 43 c6 45 ed 30 c6 45 ee 30 c6 45 ef 30 c6 45 f0 30 c6 45 f1 30 c6 45 f2 30 c6 45 f3 35 c6 45 f4 00}  //weight: 2, accuracy: High
        $x_1_2 = {c6 45 f8 49 c6 45 f9 4f c6 45 fa 56 c6 45 fb 41 c6 45 fc 53 c6 45 fd 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_CCJX_2147927764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.CCJX!MTB"
        threat_id = "2147927764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a 0c 01 30 0c 17 47 3b 7d ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GTM_2147928151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GTM!MTB"
        threat_id = "2147928151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4b 65 95 ef 60 b4 5a 30 28 ed 61 51 ea}  //weight: 10, accuracy: High
        $x_1_2 = "TJprojMain.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GTM_2147928151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GTM!MTB"
        threat_id = "2147928151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 14 10 33 ca 8b 85 ?? ?? ?? ?? 03 45 f8 88 08}  //weight: 5, accuracy: Low
        $x_5_2 = {03 45 f8 0f be 08 8b 55 f8 81 e2 07 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GTM_2147928151_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GTM!MTB"
        threat_id = "2147928151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 4c 05 ?? 8d 34 71 33 75 ?? 40 83 f8}  //weight: 5, accuracy: Low
        $x_5_2 = {8a 44 0d d4 32 04 3a 32 c2 41 83 f9 ?? 88 04 3a ?? ?? 33 c9 42 3b d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNAA_2147928337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNAA!MTB"
        threat_id = "2147928337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {45 78 70 6c 6f 72 65 72 00 55 70 64 61 74 65 48 6f 73 74 [0-160] 00 4e 49 43 4b 20 [0-64] 55 53 45 52 20}  //weight: 3, accuracy: Low
        $x_2_2 = "%s:*:enabled:@shell32.dll,-1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_YAE_2147928456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.YAE!MTB"
        threat_id = "2147928456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 c3 e9 60 05 00 32 c3 8d 3f 02 c3 32 c3 8d 3f e9}  //weight: 10, accuracy: Low
        $x_1_2 = {5f 63 40 67 30 51 c3 32 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_YAI_2147928748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.YAI!MTB"
        threat_id = "2147928748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {ac 02 c3 32 c3 02 c3 32 c3 2a c3 32 c3 2a c3 c0 c8 2d aa 83}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GC_2147928785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GC!MTB"
        threat_id = "2147928785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c3 02 c3 32 c3 2a c3 32 c3 2a c3 c0 c8 78 aa 83 c1 ff ac 02 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GD_2147928960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GD!MTB"
        threat_id = "2147928960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c3 02 c3 32 c3 2a c3 32 c3 2a c3 c0 c8 ?? aa 83 c1 ff ac 02 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BN_2147929002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BN!MTB"
        threat_id = "2147929002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4c 00 32 c8 68 ?? ?? 4c 00 88 0d ?? ?? 4c 00 8a 0d ?? ?? 4c 00 80 c9 0c c0 e9 02 81 e1 ff 00 00 00 89 4c 24 04 db 44 24 04 dc 3d}  //weight: 4, accuracy: Low
        $x_1_2 = "{A910187F-0C7A-45AC-92CC-9EDAFB757B53}" ascii //weight: 1
        $x_4_3 = {83 ec 10 8b 44 24 00 68 64 e0 4c 00 6a 00 8d 4c 24 0c 6a 01 51 c7 44 24 14 0c 00 00 00 89 44 24 18 c7 44 24 1c 00 00 00 00 ff 15 ?? ?? 4c 00 a3 ?? ?? 4d 00 83 c4 10 c3}  //weight: 4, accuracy: Low
        $x_1_4 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? f5 ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_AKHA_2147929047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AKHA!MTB"
        threat_id = "2147929047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? b7 4c 00 68 ?? 55 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 4e 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4e 4d 00 c1 e1 08 03 ca 89 0d ?? 4e 4d 00 c1 e8 10 a3 ?? 4e 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZUS_2147929114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZUS!MTB"
        threat_id = "2147929114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {50 68 04 00 00 80 6a 00 68 cb f9 1d 00 68 04 00 00 80 6a 00 68 d2 f9 1d 00 68 06 00 00 00 bb 90 5a 14 00}  //weight: 3, accuracy: High
        $x_2_2 = {50 68 04 00 00 80 6a 00 68 d3 f7 1d 00 68 04 00 00 80 6a 00 68 dc f7 1d 00 68 06 00 00 00 bb 90 5a 14 00}  //weight: 2, accuracy: High
        $x_1_3 = {50 68 04 00 00 80 6a 00 68 c6 f8 1d 00 68 04 00 00 80 6a 00 68 d0 f8 1d 00 68 06 00 00 00 bb 90 5a 14 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ANHA_2147929168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ANHA!MTB"
        threat_id = "2147929168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c7 4c 00 68 ?? 65 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 5e 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5e 4d 00 c1 e1 08 03 ca 89 0d ?? 5e 4d 00 c1 e8 10 a3 ?? 5e 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GNT_2147929219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GNT!MTB"
        threat_id = "2147929219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 6a ff 68 ?? a7 4c 00 68 ?? 45 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? ?? ?? 33 d2 8a d4 89 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GE_2147929222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GE!MTB"
        threat_id = "2147929222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 26 02 c3 32 c3 02 c3 32 c3 2a c3 32 c3 2a c3 c0 c8 e4 aa 83 c1 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GE_2147929222_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GE!MTB"
        threat_id = "2147929222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 3f 02 c3 8d 3f 8d 3f 8d 3f 32 c3 8d 3f 02 c3 32 c3 8d 3f 8d 3f 2a c3 8d 3f 8d 3f 32 c3 8d 3f}  //weight: 3, accuracy: Low
        $x_2_2 = {8d 3f 8d 3f 2a c3 8d 3f 8d 3f 8d 3f c0 c0 ?? 8d 3f 8d 3f aa 8d 3f 8d 3f 8d 3f 83 c1 ff ac 8d 3f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AQHA_2147929229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AQHA!MTB"
        threat_id = "2147929229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? ca 4c 00 68 ?? 5b 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 6d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 6d 4d 00 c1 e1 08 03 ca 89 0d ?? 6d 4d 00 c1 e8 10 a3 ?? 6d 4d 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? ca 4c 00 68 ?? 5a 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 6d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 6d 4d 00 c1 e1 08 03 ca 89 0d ?? 6d 4d 00 c1 e8 10 a3 ?? 6d 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_NIT_2147929286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NIT!MTB"
        threat_id = "2147929286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 e8 dc 62 00 ff 15 2c 62 46 00 8b 54 24 20 8b 42 20 50 ff 15 20 62 46 00 8b 4c 24 20 6a 00 6a 14 8b 51 28 52 ff 15 24 62 46 00 5f 5e 5d b8 01 00 00 00 5b 83 c4 08}  //weight: 2, accuracy: High
        $x_2_2 = {51 a1 10 d8 62 00 33 d2 3b c2 75 1a 33 c0 88 80 10 d7 62 00 40 3d 00 01 00 00 7c f2 c7 05 10 d8 62 00 01 00 00 00 8b 44 24 0c 53 8b 5c 24 14}  //weight: 2, accuracy: High
        $x_2_3 = {50 ff 15 ac 63 46 00 85 c0 0f 84 b4 00 00 00 a1 60 dc 62 00 25 ff ff 00 00 50 ff 15 d4 63 46 00 8b f0 85 f6 75 10 ff 15 f8 63 46 00 5f}  //weight: 2, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\W32Time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_KKA_2147929325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.KKA!MTB"
        threat_id = "2147929325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 18 c7 44 24 0c 60 1a 40 00 c7 44 24 08 64 00 00 00 c7 44 24 04 01 00 00 00 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 10 89 c7 c7 44 24 0c a0 19 40 00 c7 44 24 08 64 00 00 00 c7 44 24 04 02 00 00 00 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 10 89 85 3c f9 ff ff c7 44 24 0c 8c 18 40 00 c7 44 24 08 64 00 00 00 c7 44 24 04 03 00 00 00 c7 04 24 00 00 00 00 e8 ?? ?? ?? ?? 83 ec 10 89 85 40 f9 ff ff c7 44 24 0c c4 17 40 00 c7 44 24 08 64 00 00 00 c7 44 24 04 04 00 00 00 c7 04 24 00 00 00 00 e8}  //weight: 10, accuracy: Low
        $x_4_2 = {c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 89 5c 24 0c c7 44 24 08 24 40 40 00 c7 44 24 04 34 40 40 00 c7 04 24 00 00 00 00 e8}  //weight: 4, accuracy: High
        $x_6_3 = "libgcj_s.dll" ascii //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMCX_2147929518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMCX!MTB"
        threat_id = "2147929518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 00 80 06 00 00 10 00 00 00 80 06 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d4 05 00 00 00 90 06 00 00 06 00 00 00 90 06 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AMCY_2147929781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AMCY!MTB"
        threat_id = "2147929781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf 39 4c 24 ?? 76 19 83 7c 24 ?? 0f 8d 44 24 ?? 0f 47 44 24 ?? 80 34 08 52 41 3b 4c 24 ?? 72 ?? 8d 54 24 ?? 8d 4c 24 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AAIA_2147929792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AAIA!MTB"
        threat_id = "2147929792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? b3 4c 00 68 ?? 4d 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 2d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 2d 4d 00 c1 e1 08 03 ca 89 0d ?? 2d 4d 00 c1 e8 10 a3 ?? 2d 4d 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? c3 4c 00 68 ?? 5d 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 3d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 3d 4d 00 c1 e1 08 03 ca 89 0d ?? 3d 4d 00 c1 e8 10 a3 ?? 3d 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_EAKJ_2147929831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EAKJ!MTB"
        threat_id = "2147929831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b d8 88 5d fc 8b 45 e8 03 45 f4 8a 4d fc 88 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GF_2147929957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GF!MTB"
        threat_id = "2147929957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c3 02 c3 32 c3 2a c3 32 c3 2a c3 c0 c8 04 aa 83 c1 ff ac 02 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNAM_2147930041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNAM!MTB"
        threat_id = "2147930041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {e0 c9 1c ee b9 d0 8a a5 70 87 6d 87 fd 06 c2 db 15 35 ef c6 0b ed 5c a5 96 56 94 d2 f2 48 fc cb 0f d2 73 1a 88 22 32 bd 94 c1 67 0a 55 00 18 66 20 77 4f dd 92 b7 9f fc 46 b3 db ab 6a 7e 37 45 bc 38 9f 6b d9 1f ed 67 c8 e4 6f 1c 2c 57 67 c5 46 5a 6c d7 7b 90 34 1d ad b1 73 a0 34 18 be a7 3d 6b 48 90 b8 8d 6e 16 88 bf 93 9d 76 f9 b7 f5}  //weight: 4, accuracy: High
        $x_3_2 = {2e 74 65 78 74 00 00 00 cd b7 08 00 00 10 00 00 00 c0 08 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 e0 2e 72 64 61 74 61 00 00 12 08 04 00 00 d0 08 00 00 10 04 00 00 d0 08 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 4a 32 04 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 65 78 74 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 00 e0}  //weight: 3, accuracy: Low
        $x_1_3 = {e0 c9 1c ee b9 d0 8a a5 70 87 6d 87 fd 06 c2 db 15 35 ef c6 0b ed 5c a5 96 56 94 d2 f2 48 fc cb 0f d2 73 1a 88 22 32 bd 94 c1 67 0a 55 00 18 66 20 77 4f dd 92 b7 9f fc 46 b3 db ab 6a 7e 37 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PA_2147930580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PA!MTB"
        threat_id = "2147930580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "riotclient" ascii //weight: 1
        $x_3_2 = {fe c3 8a 04 1e 02 d0 86 04 16 88 04 1e 02 04 16 8a 04 06 30 07 47 49 75}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNAK_2147931009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNAK!MTB"
        threat_id = "2147931009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 20 05 00 00 10 00 00 00 20 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 30 05 00 00 04 00 00 00 30 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 40 05 00 00 02 00 00 00 34 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 74 61 67 67 61 6e 74 00 30 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {02 00 40 80 00 00 10 00 00 10 00 00 00 00 10 00 00 10 00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 59 40 05 00 6d 00 00 00 00 30 05 00 b0 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f8 41 05 00 08 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNAN_2147931546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNAN!MTB"
        threat_id = "2147931546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {49 00 6e 00 6e 00 6f 00 20 00 53 00 65 00 74 00 75 00 70 00 2e 00 00 00 00 00 9a 00 3d 00 01 00 43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 32 00 30 00 31 00 37 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 00 00 00 00 a2 00 3d 00 01 00 46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00}  //weight: 2, accuracy: High
        $x_2_2 = {76 c9 48 4d e4 a7 93 39 3b 35 b8 b2 ed 53 e5 5d}  //weight: 2, accuracy: High
        $x_1_3 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 49 6e 6e 6f 20 53 65 74 75 70 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBWQ_2147931705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBWQ!MTB"
        threat_id = "2147931705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 58 53 56 57 89 65 e8 ff 15 ?? 83 63 00 33 d2 8a d4 89 15 44 0d 64 00 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBWQ_2147931705_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBWQ!MTB"
        threat_id = "2147931705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {91 4c 00 33 d2 8a d4 89 15 90 fb 4c 00 8b c8 81 e1 ff 00 00 00 89 0d 8c fb 4c 00 c1 e1 08 03 ca 89 0d 88 fb 4c}  //weight: 2, accuracy: High
        $x_1_2 = {55 8b ec 6a ff 68 ?? 92 4c 00 68 ?? 4c 4c 00 64 a1 00 00 00 00 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AXJA_2147931986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AXJA!MTB"
        threat_id = "2147931986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 97 63 00 68 ?? 39 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 2d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 2d 64 00 c1 e1 08 03 ca 89 0d ?? 2d 64 00 c1 e8 10 a3 ?? 2d 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EACQ_2147932047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EACQ!MTB"
        threat_id = "2147932047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 45 fc 8b 45 e8 03 45 f4 8a 4d fc 88 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BW_2147932368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BW!MTB"
        threat_id = "2147932368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {99 31 d0 29 d0 89 c2 83 fa ff 0f 93 c0 0f b6 c0 f7 d8 29 c2}  //weight: 3, accuracy: High
        $x_2_2 = {01 d0 31 cb 89 da 88 10 83 45}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GNQ_2147933399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GNQ!MTB"
        threat_id = "2147933399"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 00 80 72 02 00 80 3a 9b 00 00 94 02 00 80 48 9b 00 00 5e 9b 00 00}  //weight: 10, accuracy: High
        $x_1_2 = "bbggtth.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZA_2147934003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZA!MTB"
        threat_id = "2147934003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c6 45 d4 f7 c6 45 d5 59 c6 45 d6 57 c6 45 d7 af c6 45 d8 3a c6 45 d9 5e c6 45 da ee c6 45 db c0 c6 45 dc 43 c6 45 dd ee c6 45 de 9a c6 45 df 39 c6 45 e0 9d c6 45 e1 71 c6 45 e2 92 c6 45 e3 8a c6 45 e4 4f c6 45 e5 b3 c6 45 e6 a3 c6 45 e7 3b c6 45 e8 52}  //weight: 2, accuracy: High
        $x_1_2 = {c6 45 d9 fe c6 45 da c4 c6 45 db 9e c6 45 dc d8 c6 45 dd 87 c6 45 de 49 c6 45 df 65 c6 45 e0 5a c6 45 e1 98 c6 45 e2 82 c6 45 e3 2c c6 45 e4 28 c6 45 e5 ce c6 45 e6 89 c6 45 e7 6f c6 45 e8 b3 c6 45 e9 65 c6 45 ea e9 c6 45 eb 70 c6 45 ec 1b c6 45 ed 0b c6 45 ee 9c c6 45 ef d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GNN_2147934457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GNN!MTB"
        threat_id = "2147934457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec ?? 89 45 ?? ?? ?? c7 04 24 65 00 00 00 a1 ?? ?? ?? ?? ff d0 83 ec ?? 8b 45 ?? 89 44 24 ?? 8b 45 ?? 89 04 24 a1 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AJMA_2147934504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AJMA!MTB"
        threat_id = "2147934504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 94 63 00 68 ?? 35 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 17 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 17 64 00 c1 e1 08 03 ca 89 0d ?? 17 64 00 c1 e8 10 a3 ?? 17 64 00 33 f6 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SOI_2147934650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SOI!MTB"
        threat_id = "2147934650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff 15 d8 ab 40 00 8d 85 f0 fc ff ff 48 8d 49 00 8a 48 01 40 84 c9 75 f8 66 8b 0d 1c 72 40 00 8a 15 1e 72 40 00 66 89 08 88 50 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AZSY_2147934873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AZSY!MTB"
        threat_id = "2147934873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 68 5e a7 c0 e3 8b 55 e8 8b 02 50 e8 ?? ?? ?? ?? 83 c4 0c 8b 4d e8 89 41 78 8b 45 e8 83 78 78 00 75 07 32 c0 e9 ?? ?? ?? ?? 8b 45 e8 8b 48 08 51 68 1e a7 1e 2f 8b 55 e8 8b 02 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ATMA_2147934912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ATMA!MTB"
        threat_id = "2147934912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 93 63 00 68 ?? 33 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 08 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 08 64 00 c1 e1 08 03 ca 89 0d ?? 08 64 00 c1 e8 10 a3 ?? 08 64 00 33 f6 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MHS_2147934991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MHS!MTB"
        threat_id = "2147934991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 66 6f 72 74 b9 69 6e 65 74 33 06 33 4e 04 09 c1}  //weight: 2, accuracy: High
        $x_1_2 = "my_new_hook_project.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_ACNA_2147935202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.ACNA!MTB"
        threat_id = "2147935202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 96 63 00 68 ?? 39 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 28 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 28 64 00 c1 e1 08 03 ca 89 0d ?? 28 64 00 c1 e8 10 a3 ?? 28 64 00 33 f6 56}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_KNP_2147935235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.KNP!MTB"
        threat_id = "2147935235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ce b8 b5 d9 dd 0d 83 e1 07 ba 71 ff 4b a1 c1 e1 03 e8 e4 48 00 00 30 04 3e 83 c6 01 83 d3 00 75 05 83 fe 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_INC_2147935316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.INC!MTB"
        threat_id = "2147935316"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {53 55 bb 95 1f 24 2d 9c bd 16 51 af 27 f7 d3}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPOG_2147935886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPOG!MTB"
        threat_id = "2147935886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 00 00 c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 36 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SQ_2147935952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SQ!MTB"
        threat_id = "2147935952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 1f 8b 55 08 03 55 fc 8b 45 0c 03 45 fc 8a 08 88 0a 83 7d fc 00 75 07 c7 45 fc 00 00 00 00 eb d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BE_2147936298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BE!MTB"
        threat_id = "2147936298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 04 30 30 04 39 41 3b ca 7c}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 8b cf 56 56 53 6a 2d 5a e8}  //weight: 1, accuracy: High
        $x_2_3 = "sCB.passwords.%u.txt" wide //weight: 2
        $x_2_4 = "Credentials.%u.txt" wide //weight: 2
        $x_2_5 = "sCB.cards.%u.txt" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SHS_2147936305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SHS!MTB"
        threat_id = "2147936305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 72 73 72 63 00 00 00 ac 01 00 00 00 50 81 00 00 02 00 00 00 9c 29 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 60 81 00 00 02 00 00 00 9e 29}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SSP_2147936307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SSP!MTB"
        threat_id = "2147936307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 20 00 90 05 00 00 10 00 00 00 9a 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 88 03 00 00 00 a0 05 00 00 04 00 00 00 aa 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 b0 05 00 00 02 00 00 00 ae 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PGY_2147936854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PGY!MTB"
        threat_id = "2147936854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 f2 55 48 83 c0 01 88 50 ff 0f b6 10 84 d2 75 ef}  //weight: 5, accuracy: High
        $x_5_2 = {83 f1 55 48 83 c2 01 88 4a ff 0f b6 0a 84 c9 75 ef}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_PGY_2147936854_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PGY!MTB"
        threat_id = "2147936854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 73 00 76 00 63 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_4_2 = {8b f9 89 7d f0 8b 75 08 33 db 89 1f 89 5f 04 89 5f 08 8b 4e 0c 89 4f 0c 8b 01 ff 50 04 89 5d fc 8b 36 85 f6}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SCPC_2147936929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SCPC!MTB"
        threat_id = "2147936929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 70 52 00 00 10 00 00 00 ea 1f 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 bc 0a 01 00 00 80 52 00 00 0c 01 00 00 fa 1f 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SED_2147936960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SED!MTB"
        threat_id = "2147936960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QAXiML88dr2" ascii //weight: 2
        $x_2_2 = "cancro maledetto" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_JKT_2147937368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.JKT!MTB"
        threat_id = "2147937368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c9 0f b6 c3 0f af c8 8b 44 24 10 02 0c 28 32 d1 8b c8 41 89 4c 24 10 83 f9 04 7c e2 88 14 33 43 3b df 72 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SYU_2147937381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SYU!MTB"
        threat_id = "2147937381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 8d 20 fe ff ff 83 c1 01 89 8d 20 fe ff ff 81 bd 20 fe ff ff 30 75 00 00 7d 65 e8 80 00 00 00 99 b9 fe 00 00 00 f7 f9 52 e8 72 00 00 00 99 b9 fe 00 00 00 f7 f9 52 8b 95 24 fe ff ff 52}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EAET_2147937894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EAET!MTB"
        threat_id = "2147937894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d0 8b d8 c1 ea 18 c1 eb 10 0f b6 d2 0f b6 92 ?? ?? ?? ?? 88 5c 24 11 8b d8 0f b6 c0 8a 80 ?? ?? ?? ?? 88 44 24 0f 33 c0 88 54 24 0c}  //weight: 5, accuracy: Low
        $x_5_2 = {01 d1 01 d0 c7 01 4d 4a 43 3b 01 d1 01 d0 c7 01 44 36 4f a1 01 d1 01 d0 89 ec}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PGZ_2147938068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PGZ!MTB"
        threat_id = "2147938068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 3b 09 c8 81 c3 04 00 00 00 46 46 39 d3 75 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SPDH_2147938958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SPDH!MTB"
        threat_id = "2147938958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 29 16 00 00 83 ec 0c 89 c3 c7 44 24 04 ?? ?? ?? ?? 89 04 24 e8 d4 13 00 00 83 ec 08 89 c6 85 c0 0f 85 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 ec 04 66 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAA_2147939510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAA!MTB"
        threat_id = "2147939510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c5 89 45 fc 53 56 57}  //weight: 1, accuracy: High
        $x_2_2 = {89 45 e0 64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 00 8b 00 8b 40 18}  //weight: 2, accuracy: High
        $x_1_3 = {ff d0 85 c0 0f 84 ?? ?? ?? ?? 83 f8 57 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zusy_PGS_2147939662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PGS!MTB"
        threat_id = "2147939662"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {21 86 72 3c bd 47 2b a2 7c 1c b3 63 39 86 72 24 bd 47 33 a2 7c 04 b3 63 31 86 72 2c bd 47 3b a2 7c 0c b3 23 bf 05 fb 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PGC_2147939663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PGC!MTB"
        threat_id = "2147939663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 74 65 78 74 00 00 00 10 6f 00 00 00 10 00 00 00 70 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 e0}  //weight: 1, accuracy: High
        $x_4_2 = {2e 72 64 61 74 61 00 00 34 6b 07 00 00 ?? 00 00 00 6c 07 00 00 7a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HNT_2147940510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HNT!MTB"
        threat_id = "2147940510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ec 5c 00 00 00 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 13 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? ?? ff 55 8b ec 81}  //weight: 5, accuracy: Low
        $x_5_2 = {ec 5c 00 00 00 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 13 00 90 90 90 90 90 90 90 90 90 90 e9 ?? ?? ?? ff 55 8b ec 81}  //weight: 5, accuracy: Low
        $x_5_3 = {ff c3 8b ec 81 ec 5c 00 00 00 c7 45 fc 00 00 00 00 c7 45 f8 00 00 0e 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? e9 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_5_4 = {55 8b ec 81 ec 5c 00 00 00 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 0f 00 68 ?? ?? ?? ?? e8 ?? 00 00 00 e9}  //weight: 5, accuracy: Low
        $x_5_5 = {e8 05 00 00 00 e9 ?? ?? ?? ?? 55 8b ec 81 ec 5c 00 00 00 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 00 00 00 00}  //weight: 5, accuracy: Low
        $x_5_6 = {55 8b ec 81 ec 5c 00 00 00 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 c7 45 f4 00 00 00 00 c7 45 f0 0f 00 68 ?? ?? ?? ?? 90 ?? ?? ?? ?? e9 ?? ?? ?? ?? 55}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_SCP_2147940664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SCP!MTB"
        threat_id = "2147940664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 50 06 00 00 10 00 00 00 bc 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 f0 c9 30 00 00 60 06 00 00 bc 25 00 00 cc 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAB_2147941282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAB!MTB"
        threat_id = "2147941282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1b c0 53 83 e0 02 0c 20 50 6a 02 53 6a 01 68 ?? ?? ?? ?? ff 75 08 ff 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AUZ_2147941893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AUZ!MTB"
        threat_id = "2147941893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 e6 8b 45 f4 01 d0 0f b6 18 c7 04 24 1c e0 a4 6c e8 ?? ?? ?? ?? 8b 55 f4 01 d0 83 c0 0a 88 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_EZV_2147942202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.EZV!MTB"
        threat_id = "2147942202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 55 f0 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 e0 01 d0 89 c2 8d 45 d4 89 44 24 04 89 14 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAE_2147942206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAE!MTB"
        threat_id = "2147942206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 8c 8a 44 15 98 30 04 0f 47 81 ff ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBWM_2147942276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBWM!MTB"
        threat_id = "2147942276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 72 64 61 74 61 00 00 8e 9d 01 00 00 c0 0d 00 00 a0 01 00 00 c0 0d 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 0a 05 05 00 00 60 0f 00 00 80 01 00 00 60 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 72 73 72 63 00 00 00 10 5d 00 00 00 70 14 00 00 60 00 00 00 e0 10 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40}  //weight: 2, accuracy: High
        $x_2_2 = {2e 74 65 78 74 00 00 00 e6 a6 0d 00 00 10 00 00 00 b0 0d 00 00 10}  //weight: 2, accuracy: High
        $x_1_3 = {33 c0 c3 90 85 db 75 03 33 c0 c3 8b cb f7 c1 03 00 00 00 74 0f 8a 01 41 84 c0 74 3b f7 c1 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MBWN_2147942277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MBWN!MTB"
        threat_id = "2147942277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 65 78 74 00 00 00 06 9c 0d 00 00 10 00 00 00 a0 0d 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 64 61 74 61 00 00 5e 9d 01 00 00 b0 0d 00 00 a0 01 00 00 b0 0d 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 0a 05 05 00 00 50 0f 00 00 80 01 00 00 50 0f 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 72 73 72 63 00 00 00 9a 18 00 00 00 60 14 00 00 20 00 00 00 d0 10 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PGZY_2147943226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PGZY!MTB"
        threat_id = "2147943226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {39 db 74 01 ea 31 ?? ?? ?? 81 c3 04 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HBD_2147943583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HBD!MTB"
        threat_id = "2147943583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff 74 24 10 ff 74 24 10 83 04 24 05 ?? ?? ?? ?? ?? 8f 44 24 28 8f 44 24 28 ff 74 24 08 ff 74 24 08 8d 44 24 2c 8b 10 29 14 24 8b 50 04 19 54 24 04 8f 44 24 30 8f 44 24 30 ff 74 24 30 ff 74 24 30 5b 5f 83 ff 00 7f 0b 7c 05 83 fb 05 77 04 ?? c0 eb 05}  //weight: 10, accuracy: Low
        $x_1_2 = {89 44 24 34 8b 44 24 2c 50 ff 74 24 38 ff 74 24 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LMA_2147943593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LMA!MTB"
        threat_id = "2147943593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 e1 04 33 c2 03 f9 6a 00 6a 02 89 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 32 d1 8b 44 24 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 80 ca 0c 50 c0 ea 02 81 e2 ff 00 00 00 89 54 24 0c db 44 24 0c}  //weight: 2, accuracy: Low
        $x_1_2 = {50 64 89 25 00 00 00 00 83 ec 1c 53 56 57 89 65 e8 9b 33 ff 89 7d fc}  //weight: 1, accuracy: High
        $x_1_3 = {40 4e e6 40 bb fe ff ff ff 7b}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 6a 00 68 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff d0 ff d7 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAC_2147944114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAC!MTB"
        threat_id = "2147944114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 14 10 33 ca 8b 45 08 03 45 98 0f b6 30}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAC_2147944114_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAC!MTB"
        threat_id = "2147944114"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 62 00 00 00 f3 a4 8d 85 62 ff ff ff 89 04 24 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAF_2147944120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAF!MTB"
        threat_id = "2147944120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 52 0c 8a 14 1a 8a 1c 39 32 d3 83 c6 01 88 14 01 8b 45 ?? 0f 80}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LM_2147944138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LM!MTB"
        threat_id = "2147944138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 c5 81 c0 4c 00 00 00 b9 da 05 00 00 ba 85 3c de 9f 30 10 40 49}  //weight: 2, accuracy: High
        $x_1_2 = {b0 c0 bc 40 0b b0 c0 bc 8b 00 97 37 37 37 34 c9 ba 69 37 a1 bc 47 0b a1 bc b3 07 03 37 37 37 1c ef bc 60 37 b0 ce bc 4e 33 b0 ce}  //weight: 1, accuracy: High
        $x_1_3 = {00 dc 02 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 00 00 00 00 00 00 00 00 00 80 00 00 00 30 15 00 00 66 00 00 00 dc 08 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LM_2147944138_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LM!MTB"
        threat_id = "2147944138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 f0 8b 45 f4 01 d0 0f b6 00 89 c2 8b 45 e8 89 d1 31 c1 8b 55 f0 8b 45 f4 01 d0 89 ca 88 10}  //weight: 2, accuracy: High
        $x_1_2 = {8b 55 d8 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 c8 01 d0 8b 40 08 8d 95 7c ff ff ff 89 54 24 0c 8b 55 d4 89 54 24 08 89 44 24 04 8b 45 a4 89 04 24 a1 74 20 40 00 ff d0 83 ec 10}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 f0 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 e0 01 d0 89 c2 8d 45 d4 89 44 24 04 89 14 24 e8 ?? ?? ?? ?? 85 c0 75 ?? 8b 55 f0 89 d0 c1 e0 02 01 d0 c1 e0 03 89 c2 8b 45 e0 01 d0 8b 50 0c 8b 45 ec 01 d0 89 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GDF_2147944142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GDF!MTB"
        threat_id = "2147944142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f0 01 d0 0f b6 00 01 c8 0f b6 c0 0f b6 8c 05 ?? ?? ?? ?? 8b 55 08 8b 45 ec 01 d0 31 cb 89 da 88 10 83 45 ec 01 8b 45 ec 3b 45 0c 0f 82}  //weight: 10, accuracy: Low
        $x_10_2 = {89 e5 83 ec 14 8b 45 10 88 45 ec c7 45 fc 00 00 00 00 ?? ?? 8b 55 08 8b 45 fc 01 d0 0f b6 00 8b 4d 08 8b 55 fc 01 ca 32 45 ec 88 02 83 45 fc 01 8b 45 fc 3b 45 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_HBE_2147944371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HBE!MTB"
        threat_id = "2147944371"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 05 00 00 00 e9 ?? ?? ?? ?? 83 c0 0f 8b 3c 24 29 c7 01 fb e8 4a 00 00 00 85 c0 75 01 c3 89 c1 51 be ?? ?? ?? ?? 01 fe ff 16 85 c0 75 0b e8 3c 00 00 00 85 c0 75 f7 eb db 89 c1 e8 23 00 00 00 85 c0 74 d0 50 51 be ?? ?? ?? ?? 01 fe ff 16 89 c6 e8 0d 00 00 00 85 c0 75 01 c3 85 f6 74 02 89 30 eb d6 e8 07 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LME_2147944504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LME!MTB"
        threat_id = "2147944504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {c7 45 a4 8a a5 08 00 bb e3 14 00 00 c7 45 c4 9f 0a 00 00 89 65 fc 81 45 fc 64 02 00 00 89 6d f8 81 45 f8 c0 01 00 00 8d 0d 68 a6 48 00 8b 41 f0 89 45 f4 8b 41 ec 89 45 f0 c7 45 d8 c0 70 2c 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 0d 68 a6 48 00 b2 01}  //weight: 20, accuracy: Low
        $x_10_2 = {33 c0 89 43 60 33 c0 89 83 84 00 00 00 c7 43 5c 18 00 00 ff c7 43 78 f4 01 00 00 c6 43 7c 01 33 c0 89 83 80 00 00 00 c7 43 74 c4 09 00 00 c6 83 88 00 00 00 00 c6 83 9d 00 00 00 01 c6 83 b4 00 00 00 01 b2 01 a1}  //weight: 10, accuracy: High
        $x_5_3 = "qetwetrqwer" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AO_2147944850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AO!MTB"
        threat_id = "2147944850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 40 08 03 45 f8 8b 4d 08 99 f7 79 04 8b 45 08 8b 08 8b 45 f8 8b 75 f4 8b 0c 91 89 0c 86 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AP_2147944996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AP!MTB"
        threat_id = "2147944996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 e5 d7 59 4b 19 83 0c 87 46 81 30 8e bf 0b e9 b0 3c 14 70 e3 ee 48 4c 7e 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AQ_2147945005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AQ!MTB"
        threat_id = "2147945005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 33 ca 42 03 1d 41 5f 53 00 87 c1 87 c1 4a 33 ca 43 21 0d 3d 5c 53 00 81 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AS_2147945008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AS!MTB"
        threat_id = "2147945008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c3 83 e3 0f 0f b6 3c 31 89 fd 83 e5 0f 01 eb 21 c5 01 ed 29 eb 89 c5 c1 ed 04 33 2c 9d fc 16 45 00 89 e8 83 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAG_2147945048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAG!MTB"
        threat_id = "2147945048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 a4 c1 e0 05 89 c2 8b 45 a4 01 c2 8b 45 a0 01 d0 89 45 a4 8b 45 a8 8d 50 01 89 55 a8 0f b6 00 0f be c0 89 45 a0 83 7d a0 00 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HC_2147945283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HC!MTB"
        threat_id = "2147945283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 45 00 00 4c 01 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 65 78 74 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 67 66 63 64 00 00 00 00 10 00 00 ?? ?? ?? ?? 00 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MR_2147945546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MR!MTB"
        threat_id = "2147945546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {8b ec 83 c4 b0 8b 45 10 40 8a 10 80 fa 20}  //weight: 25, accuracy: High
        $x_10_2 = {68 fa 00 00 00 68 29 30 40 00 6a ff 68 23 31 40 00 6a 00 6a 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MR_2147945546_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MR!MTB"
        threat_id = "2147945546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "64A1300000008B40108B403C89442404C9C3" ascii //weight: 5
        $x_15_2 = {8d 85 5c ff ff ff 50 8d 85 60 ff ff ff 50 8d 85 64 ff ff ff 50 8d 85 68 ff ff ff 50 8d 85 6c ff ff ff 50 8d 45 c0 50 8b 45 08 8b 00 ff}  //weight: 15, accuracy: High
        $x_10_3 = {89 45 84 c7 45 a4 02 00 00 00 c7 45 9c 02 00 00 00 c7 45 b4 34 63 40 00 c7 45 ac 08 00 00 00 8d 45 c0}  //weight: 10, accuracy: High
        $x_25_4 = {8b 45 e4 8b 00 99 2b c2 d1 f8 8b 55 c8 88 0c 02 8d 45 a8 50 8d 45 ac 50 6a 02}  //weight: 25, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AF_2147945986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AF!MTB"
        threat_id = "2147945986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 01 8b 51 04 89 46 04 8b 46 08 89 56 0c 8b 48 04 89 4e 10 89 d1 8b 10 8b 46 04 33 4e 10 31 d0 89 56 14 31 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AHC_2147946024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AHC!MTB"
        threat_id = "2147946024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 45 fc 8b 55 f4 8a 44 10 ff 8b 55 f8 8a 54 1a ff 32 c2 25 ff 00 00 00 8d 4d f0 ba 02 00 00 00 e8}  //weight: 3, accuracy: High
        $x_2_2 = {8a 54 1f ff 0f b7 ce c1 e9 08 32 d1 88 54 18 ff 33 c0 8a 44 1f ff 66 03 f0 66 0f af 35 ?? ?? ?? 00 66 03 35 ?? ?? ?? 00 43 ff 4d f8 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AHD_2147946025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AHD!MTB"
        threat_id = "2147946025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 55 08 8b 45 fc 01 d0 0f b6 00 32 45 ec 89 c1 8b 55 14 8b 45 fc 01 d0 89 ca 88 10 83 45 fc 01}  //weight: 3, accuracy: High
        $x_2_2 = {ff ff 76 c7 45 f0 09 00 00 00 8d 85 ?? ?? ff ff 89 44 24 0c c7 44 24 08 37 00 00 00 8b 45 f0 89 44 24 04 8d 85 ?? ?? ff ff 89 04 24 e8}  //weight: 2, accuracy: Low
        $x_1_3 = "cmd.exe /C timeout /T 1 /NOBREAK >nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LMG_2147946146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LMG!MTB"
        threat_id = "2147946146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {ff 55 10 8b 4f 54 8b 75 08 8b d1 c1 e9 02 8b f8 f3 a5 8b ca 83 e1 03 f3 a4 8b 4d 08 8b 51 3c 8b 75 f8}  //weight: 15, accuracy: High
        $x_10_2 = {8b 3c 33 8b c7 83 e0 0f c1 e0 0b 8b cf 81 e1 00 04 00 00 03 c1 8b cf c1 e9 14 81 e1 00 07 00 00 8d 34 41 89 7c 24 14 0f b6 44 24 16}  //weight: 10, accuracy: High
        $x_5_3 = {8b c6 25 00 07 00 00 c1 e0 04 8b ce 81 e1 ff 00 00 00 03 c1 8b ce d1 e9 c1 e0 10 81 e1 00 04 00 00 c1 ee 0c 03 c1 83 e6 0f 03 c6 81 e7 f0 fb 00 8f 03 c7 89 03}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AHB_2147946218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AHB!MTB"
        threat_id = "2147946218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 ca c1 e2 05 0f be c0 01 d0 01 c1 83 c3 01 0f b6 43 ff 84 c0 75}  //weight: 2, accuracy: High
        $x_1_2 = "BK: Succesfully deleted registry key: HKEY_LOCAL_MACHINE\\%s - \"%s" ascii //weight: 1
        $x_1_3 = "BK: Successfully killed Process: %s (PID: %ld)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AHF_2147946219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AHF!MTB"
        threat_id = "2147946219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b 45 e8 1c 8b 4d e0 8b 54 01 14 89 55 ac 6b 45 e8 1c 8b 4d e0 8b 54 01 10 89 55 88 8b 45 ac 25 ff ff 00 00 50 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 e0 8b 08 8b 51 10 89 55 90 6a 00 6a 00 8d 45 80 50 6a 00 68 ?? ?? ?? 10 8b 4d e0 51 ff 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SXE_2147946647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SXE!MTB"
        threat_id = "2147946647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 f6 90 8b 54 b4 14 8b 44 24 10 8d 4c 24 0c}  //weight: 5, accuracy: High
        $x_3_2 = "G3T WIND0WS D3F3ND3R N3XT TIM3!" ascii //weight: 3
        $x_1_3 = "taskmgr.exe" ascii //weight: 1
        $x_1_4 = "msconfig.exe" ascii //weight: 1
        $x_1_5 = "shutdown.exe" ascii //weight: 1
        $x_1_6 = "taskkill.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LMF_2147946817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LMF!MTB"
        threat_id = "2147946817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {33 c0 8b 55 ec 01 13 8b 75 d4 03 75 a4 03 75 ec 03 f0 bf 89 15 00 00 6a 00 e8 ?? ?? ?? ?? 03 fe 81 ef 89 15 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 31 3b 83 45 ec 04 83 c3 04 8b 45 ec 3b 45 dc}  //weight: 20, accuracy: Low
        $x_10_2 = {40 00 50 d2 40 00 d0 d0 40 00 bc da 40 00 8c da 40 00 34 35 41 00 bc 34 41 00 f8 36 41 00 c8 36 41 00 e0 3e 41 00 90 3e 41 00 78 d6 41 00 c8 d5 41 00 60 4c 42 00 30 4c}  //weight: 10, accuracy: High
        $x_5_3 = {ff 45 ec 81 7d ec 2c 8c 74 15 75 ?? c7 45 a4 8a a5 08 00 bb e3 14 00 00 c7 45 c4 9f 0a 00 00 89 65 fc 81 45 fc 64 02 00 00 89 6d f8 81 45 f8 c0 01 00 00 8d 0d 68 56 45 00 8b 41 f0 89 45 f4 8b 41 ec 89 45 f0 c7 45 d8 c0 70 2c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SXD_2147947303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SXD!MTB"
        threat_id = "2147947303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b fe 8b 36 66 83 7f 2e 00 74 23 8b 4f 30 85 c9 74 1c 51 8d 94 24 14 02 00 00 e8 ?? ?? ?? ?? 8d 94 24 10 02 00 00 51 8b ca e8 ?? ?? ?? ?? 51 8d 54 24 14 8d 8c 24 14 02 00 00 e8 ?? ?? ?? ?? 85 c0 74 08 3b f3 75 b9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HE_2147947639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HE!MTB"
        threat_id = "2147947639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 70 61 79 6c 6f 61 64 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_50_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-21] 00 6f 70 65 6e 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? (61|2d|7a|41|2d|5a|30|2d|39|2b|2f) (61|2d|7a|41|2d|5a|30|2d|39|2b|2f)}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MCF_2147947908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MCF!MTB"
        threat_id = "2147947908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 c2 d3 29 00 40 cf 27 00 2e d0 2d 00 4a cf 27 00 2e d0 23 00 43 cf 27 00 77 e9 2c 00 42 cf 27 00 77 e9 23 00 42 cf 27 00 41 cf 26 00 2c cf 27 00 a9 d0 2c 00 42}  //weight: 1, accuracy: High
        $x_1_2 = {74 53 6e 61 63 75 6f 54 20 65 76 6f 6c 20 49 50 45 00 00 4c 01 04 00 f4 68 d2 50}  //weight: 1, accuracy: High
        $x_1_3 = {40 00 00 40 2e 64 61 74 61 00 00 00 34 25 01 00 00 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GAO_2147947961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GAO!MTB"
        threat_id = "2147947961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {8b 45 f8 03 45 0c 8b 55 f8 03 55 08 8a 12 32 55 ff 88 10 ff 45 f8 fe 45 ff}  //weight: 8, accuracy: High
        $x_2_2 = "DEADBABE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LMH_2147947986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LMH!MTB"
        threat_id = "2147947986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {89 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 88 45 a3 8d 85 7c fd ff ff 8d 55 a3 89 14 24 c7 85 e8 fb ff ff 04 00 00 00 89 c1}  //weight: 20, accuracy: High
        $x_10_2 = {8d 85 64 fd ff ff c7 44 24 ?? ?? ?? ?? ?? 8d 55 a4 89 54 24 04 89 04 24 c7 85 e8 fb ff ff 06 00 00 00}  //weight: 10, accuracy: Low
        $x_5_3 = {89 c2 89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 d0 88 85 e0 fb ff ff 8b 55 dc 8d 85 7c fd ff ff 89 14 24 89 c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PWR_2147948282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PWR!MTB"
        threat_id = "2147948282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 8b 75 10 8b c1 83 e0 1f 8a 04 30 30 04 0a 41 3b 4d 0c 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NC_2147949048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NC!MTB"
        threat_id = "2147949048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {e9 32 ff ff ff 89 06 89 46 0c 89 46 10 83 c6 14 8b 95 22 04 00 00 e9 ?? ?? ff ff b8 10 c9 05 00 50 03 85 22 04 00 00 59 0b c9 89 85 a8 03 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = {eb f1 be 00 00 06 00 8b 95 22 04 00 00 03 f2 8b 46 0c 85 c0 0f 84 ?? ?? ?? ?? 03 c2 8b d8 50 ff 95 4d 0f 00 00}  //weight: 2, accuracy: Low
        $x_1_3 = "WinExec" ascii //weight: 1
        $x_1_4 = "GetAcceptExSockaddrs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_NZS_2147949140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.NZS!MTB"
        threat_id = "2147949140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 00 88 45 b4 8b 45 e8 83 e0 23 8a 4d b4 32 c8 88 4d b4 8b 45 e0 8a 4d b4 0a 4c 05 ?? 88 4d b4 8b 45 ?? 40 89 45 e0 8b 45 fc 03 45 ?? 8a 4d b4 88 08 83 7d e0 10 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MRA_2147949338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MRA!MTB"
        threat_id = "2147949338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {bf 9a 77 68 ed dc ea be ?? ?? ?? ?? f0 00 22 00 0b 02 0e 2c 00 e0 0f 00 00 90 06}  //weight: 5, accuracy: Low
        $x_5_2 = {40 00 00 40 20 20 20 20 20 20 20 20 ec a4 ?? ?? ?? 30 15 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_3 = {a0 c1 16 00 14 02 00 00 00 e0 16 00 e4 01 00 00 b8 2d 62 01 dc 4c 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MRB_2147949735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MRB!MTB"
        threat_id = "2147949735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 00 00 e0 2e 72 73 72 63 ?? ?? ?? f0 02 ?? ?? ?? 30 0e 01 00 02}  //weight: 5, accuracy: Low
        $x_2_2 = {40 00 00 c0 2e 69 64 61 74 61 20 20 00 10 ?? ?? ?? 40 0e 01 00 02}  //weight: 2, accuracy: Low
        $x_5_3 = {40 00 00 e0 63 6d 73 75 74 65 67 79 00 a0 16 00 00 e0 46 01 00 94 16 00 00 34 96 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_HF_2147949751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.HF!MTB"
        threat_id = "2147949751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "<div class=\"header\"><a><!-- img src=Corporate logo goes here></img--></a></div>" ascii //weight: 50
        $x_10_2 = "<p>Click 'OK' to continue - /</p>" ascii //weight: 10
        $x_5_3 = "window.location = \"/\";" ascii //weight: 5
        $x_5_4 = "<title>Noncompliant action</title>" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_PZY_2147950171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.PZY!MTB"
        threat_id = "2147950171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MySuperSecretKeyForAES256IsGood!" ascii //weight: 1
        $x_2_2 = "+iJuBfovHhKMKXZfVv7Tv8WYJ62/Nvgh3jDNr3UCSUZFE5lLlmSt4pL5+ZbUjcZ6TfUgnUQP92yh9qYAwk/LQQ==" ascii //weight: 2
        $x_2_3 = "Sm5hkMLdudICcfA1YqA64VA8562yICe5jP8QtdFtqyA=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_MRC_2147950550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.MRC!MTB"
        threat_id = "2147950550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 00 70 12 00 73 ?? 00 00 0a 26 06 2d 01 2a 02 02 73 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_5_2 = "$CF359F6B-AF1F-49EC-A977-81ECB3774CBE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GXT_2147950763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GXT!MTB"
        threat_id = "2147950763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 fe 0f 8d 45 d4 0f 47 c1 0f b6 0c 10 8b 45 bc 89 14 88 42 8b 4d d4 83 fa 40 7c}  //weight: 5, accuracy: High
        $x_5_2 = "iDTHNqCQGIVt0KFQUh9NyrHXKGQ7j/aa" ascii //weight: 5
        $x_1_3 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_4 = "MySuperSecretKeyForAES256IsGood!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_BAD_2147951025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.BAD!MTB"
        threat_id = "2147951025"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c1 88 85 ?? ?? ?? ?? 0f b7 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? 03 95 ?? ?? ?? ?? 8d 4c 10 2b 88 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_GXY_2147951329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GXY!MTB"
        threat_id = "2147951329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 33 d2 f7 d8 f7 f7 8b da 39 5c 24 1c ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? f7 e7 8b ca 3b c3 ?? ?? 8b 5c 24 ?? 8d 04 ?? 8b 4c 24 10 35 ?? ?? ?? ?? 8a 44 04 28 88 04 31 41 89 4c 24 ?? 83 f9 ?? 0f 82}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c6 33 d2 f7 d8 f7 f6 8b fa 39 7c 24 ?? ?? ?? 66 ?? 8d 4c 24 68 e8 ?? ?? ?? ?? f7 e6 8b ca 3b c7 ?? ?? 8b 7c 24 ?? 8d 04 19 8b 4c 24 14 35 00 00 00 80 8a 44 04 ?? 88 04 0f 47 89 7c 24 10 83 ff ?? 0f 82}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zusy_GAPJ_2147951369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.GAPJ!MTB"
        threat_id = "2147951369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "iDTHNqCQGIVt0KFQUh9NyrHXKGQ7j/aaE/SNKAszEoyZwX6Vb7GJggL5/KBLM14rSMqsGxRA+ucLjSsANNLFeQ==" ascii //weight: 8
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AU_2147951418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AU!MTB"
        threat_id = "2147951418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 10 04 01 0f 28 ca 0f 57 c2 0f 11 04 01 0f 10 84 05 40 f5 ff ff 0f 57 c2 0f 11 84 05 40 f5 ff ff 0f 10 04 02 0f 57 c8 0f 11 0c 02 0f 10 04 06 0f 57 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_AW_2147951442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.AW!MTB"
        threat_id = "2147951442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 9c c1 83 f8 09 88 d5 0f 9f c4 30 d1 30 e2 08 e5 88 d0 20 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_SXI_2147951683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.SXI!MTB"
        threat_id = "2147951683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 e9 39 88 88 ?? ?? ?? ?? 40 3b c2 7c eb}  //weight: 3, accuracy: Low
        $x_2_2 = {8d 49 00 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 8d 8d a8 fe ff ff 51 56 8b f8 ff 15 ?? ?? ?? ?? 8d 47 fe 83 f8 03}  //weight: 2, accuracy: Low
        $x_1_3 = "E:\\VS2010\\VC\\include\\" ascii //weight: 1
        $x_1_4 = "-> Hard disk" ascii //weight: 1
        $x_1_5 = "-> CD/DVD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zusy_LMB_2147952202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zusy.LMB!MTB"
        threat_id = "2147952202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 95 58 ff ff ff 83 ea 4d 0f b6 85 7e ff ff ff 23 d0 89 95 6c ff ff ff 8b 4d 14 83 c1 08 0f b6 55 97 2b 95 78 ff ff ff 0b ca 66 89 8d 50 ff ff ff 8b 45 10 83 c0 31 83 c8 45 88 45 bf b9 07 00 00 00}  //weight: 10, accuracy: High
        $x_20_2 = {2b 95 48 ff ff ff 03 15 18 10 42 00 66 89 55 f0 0f b6 45 e7 03 45 14 2b 05 18 10 42 00 03 85 78 ff ff ff 66 89 45 b4 c7 85 34 ff ff ff 48 00 00 00 0f b7 8d 5c ff ff ff 83 c1 47 2b 8d 48 ff ff ff 83 f1 3c 83 f1 2b 88 4d f8 c7 85 48 ff ff ff fc ff ff ff}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

