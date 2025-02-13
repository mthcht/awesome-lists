rule Trojan_Win32_Sabsik_RW_2147784698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RW!MTB"
        threat_id = "2147784698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 f1 8b 64 45 2d 01 f2 89 44 24 ?? 89 54 24 ?? 8b 44 24 ?? 35 e4 ae 96 27}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RW_2147784698_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RW!MTB"
        threat_id = "2147784698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 89 88 88 88 f7 e1 8b c6 c1 ea 03 8b ca c1 e1 04 2b ca 2b c1 0f b6 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 83 c6 02 81 fe 7e 07 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RW_2147784698_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RW!MTB"
        threat_id = "2147784698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptDestroyKey" ascii //weight: 1
        $x_1_2 = "DdeConnect" ascii //weight: 1
        $x_1_3 = "mpr.dll" ascii //weight: 1
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
        $x_1_5 = "K6jupsp2yWqNetsY1jBVeA9jggawc3cpMSmg162" ascii //weight: 1
        $x_1_6 = "tHqGwsKeBbME17IW7emfIbDnHhlt0UcXC24" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_DA_2147787434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.DA!MTB"
        threat_id = "2147787434"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "CopyLick? System" ascii //weight: 10
        $x_10_2 = "Display.NvContainer" ascii //weight: 10
        $x_1_3 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_4 = "AUTOIT NO CMDEXECUTE" ascii //weight: 1
        $x_1_5 = "MultiByteToWideChar" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "GetClipboardData" ascii //weight: 1
        $x_1_8 = "SwapMouseButtons" ascii //weight: 1
        $x_1_9 = "AVtype_info" ascii //weight: 1
        $x_1_10 = "GetCPInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sabsik_RM_2147789424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RM!MTB"
        threat_id = "2147789424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 39 8e e3 38 f7 e1 8b c6 c1 ea 02 8d 0c d2 03 c9 2b c1 0f b6 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 83 c6 02 81 fe 7e 07 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RM_2147789424_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RM!MTB"
        threat_id = "2147789424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "managementdicksubmenudetectsquicklyrC" ascii //weight: 1
        $x_1_2 = "qCinstallotopgunCandfor" ascii //weight: 1
        $x_1_3 = "uxplugin0points.642.1oversion" ascii //weight: 1
        $x_1_4 = "FTTTR.pdb" ascii //weight: 1
        $x_1_5 = "Dmetrics7majorn1lb654321" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RWA_2147789425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RWA!MTB"
        threat_id = "2147789425"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 7d ?? 8b 55 ?? 03 55 ?? 0f b6 0a 83 c1 47 8b 45 ?? 99 f7 7d ?? 8b 45 ?? 0f be 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RT_2147793788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RT!MTB"
        threat_id = "2147793788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 72 8b ?? ?? 99 f7 7d ?? 8b 45 ?? 0f be 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_PJRT_2147797922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.PJRT!!MTB"
        threat_id = "2147797922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 a6 d5 53 51 61 90 b3 bb 66 57 f6 b0 61 90 b3 50 ea d5 5f 91 81 94 38 1d 89 1d f7 55 c1 1b e6 b4 ec 94 7b db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_PJ_2147797977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.PJ!MTB"
        threat_id = "2147797977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b ed 02 05 66 19 70 1b a8 80 f6 3f a8 a8 f6 3f a0 a8 fe b5 7e 19 8f 22 3b 57 0e 9e 6b ed 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_PJRT_2147797978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.PJRT!MTB"
        threat_id = "2147797978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Temp" ascii //weight: 1
        $x_1_2 = "http://zloy1312.tk/ss/download.php" ascii //weight: 1
        $x_1_3 = "Server-Sided-Files-master\\Client-Side" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "CreateTask" ascii //weight: 1
        $x_1_6 = "IScheduleTrigger" ascii //weight: 1
        $x_1_7 = "RunEveryXMinutes" ascii //weight: 1
        $x_1_8 = "WriteAllBytes" ascii //weight: 1
        $x_1_9 = "UploadValues" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_POIU_2147797979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.POIU!MTB"
        threat_id = "2147797979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 13 e6 95 35 a1 08 aa 55 ba b2 5c 62 da b1 9e 9d da b1 d6 9d dd c1 e5 0e 12 de 95 25 89 09 82 55 aa aa 5d 7a da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_VBNV_2147797980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.VBNV!MTB"
        threat_id = "2147797980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 c6 48 c0 04 00 00 00 81 ef b3 7a 65 f8 39 f0 75 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_2147797982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.MTR!MTB"
        threat_id = "2147797982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTR: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c3 00 83 c3 00 83 c4 0a 83 ec 0a 83 c3 00 83 c3 00 8a 08 02 ca 32 ca 02 ca 32 ca 88 08 40 4e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_MNB_2147797985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.MNB!MTB"
        threat_id = "2147797985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 00 66 85 e1 83 e0 0f 33 c2 f7 c1 c2 4b 87 0b 81 ff 54 6c 2e 2a 81 e6 ff 00 00 00 f8 66 85 ea 33 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_REA_2147797986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.REA!MTB"
        threat_id = "2147797986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c2 66 85 ce 66 81 ca 0c 76 8b 54 24 18 88 04 2a}  //weight: 1, accuracy: High
        $x_1_2 = {88 04 29 0f be b5 c0 da 18 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Sabsik_RE_2147797987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RE!MTB"
        threat_id = "2147797987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ed 6b b1 55 b0 61 84 f5 36 14 18 29 7a d1 11 0d 98 88 6a ab bd c9 62 5c a0 eb e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RE_2147797987_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RE!MTB"
        threat_id = "2147797987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 16 8b c2 8b cb d3 e8 8b 4d 08 d3 e2 4f 8d 76 04 0b 55 fc 89 00 fc 89 56 fc 85 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_MO_2147798657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.MO!MTB"
        threat_id = "2147798657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 10 8b 4d 98 33 4d ac 8b 55 c0 89 0a 68 b5 00 00 00 8d 45 dc 50 8d 8d ac fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RF_2147799504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RF!MTB"
        threat_id = "2147799504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bjXVZgrMU9QGPsqcg2JGdCaOCK" ascii //weight: 1
        $x_1_2 = "nvRAd3ckr2wysSW2d2Wgaferrfu1ic" ascii //weight: 1
        $x_1_3 = "UnhookWindowsHookEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RF_2147799504_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RF!MTB"
        threat_id = "2147799504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\sitar\\Desktop\\40 projects\\project\\project\\Classical Dll Injection_dll\\Typical Classical Dll Injection" ascii //weight: 10
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "\\shelldoc.dll" ascii //weight: 1
        $x_1_4 = "Global\\RPCMutex" ascii //weight: 1
        $x_1_5 = "\\system32\\win32k.sys" ascii //weight: 1
        $x_1_6 = "GetCPInfo" ascii //weight: 1
        $x_1_7 = "OutputDebugStringW" ascii //weight: 1
        $x_1_8 = "connection_aborted" ascii //weight: 1
        $x_1_9 = "connection_refused" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Sabsik_ABK_2147805647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.ABK!MTB"
        threat_id = "2147805647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".cracksm" ascii //weight: 1
        $x_10_2 = "0IJDBewFGzXC9kEyVGZZWj7h6JIHYWeQj" ascii //weight: 10
        $x_1_3 = "RegOpenKeyExW" ascii //weight: 1
        $x_1_4 = "RegQueryValueExA" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_10_6 = ".\\mailslot\\system_alloc_mem3" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_DAB_2147806245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.DAB!MTB"
        threat_id = "2147806245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 08 81 e1 ff ff 00 00 c1 e1 02 01 ca 8b 3a 89 eb 81 c3 9b 00 00 00 8b 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_FG_2147806248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.FG!MTB"
        threat_id = "2147806248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 f9 03 0f b6 15 ?? ?? ?? ?? c1 e2 05 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? f7 d8 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_PJT_2147806250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.PJT!MTB"
        threat_id = "2147806250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 48 f8 8b 38 8b 50 fc 03 4d fc 03 7d 08 8b da 4a 85 db 74 0a 42 8a 1f 88 19 41 47 4a 75 f7 83 c0 28 ff 4d 0c 75 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_PJU_2147806251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.PJU!MTB"
        threat_id = "2147806251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7c 24 1c 00 74 17 8b d7 2b d3 3b c2 73 0f 83 f8 3c 72 05 83 f8 3e 76 05 c6 01 00 eb 04 8a 16 88 11 41 46 40 ff 4c 24 5c 75 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sabsik_RTH_2147807528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sabsik.RTH!MTB"
        threat_id = "2147807528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "i386\\chkesp.c" ascii //weight: 10
        $x_10_2 = "D:\\4234234234234234234234234234.pdb" ascii //weight: 10
        $x_1_3 = "GetStartupInfoA" ascii //weight: 1
        $x_1_4 = "GetLocaleInfoW" ascii //weight: 1
        $x_1_5 = "GetSystemInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

