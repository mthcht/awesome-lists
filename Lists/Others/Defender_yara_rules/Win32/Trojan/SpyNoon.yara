rule Trojan_Win32_Spynoon_KMG_2147751716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.KMG!MTB"
        threat_id = "2147751716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 0f 85 f6 75 ?? c0 e0 04 be 01 00 00 00 88 01 eb ?? 08 01 33 f6 41 42 3b ?? 72 0a 00 8a 82 ?? ?? ?? ?? 84 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {24 0f 85 c9 75 ?? c0 e0 04 b9 01 00 00 00 88 02 eb ?? 08 02 33 c9 42 46 3b f7 72 0a 00 8a 86 ?? ?? ?? ?? 84 c0 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Spynoon_PA_2147775126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.PA!MTB"
        threat_id = "2147775126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%PUBLIC%\\puttys.exe" wide //weight: 1
        $x_1_2 = "32689657.xyz" wide //weight: 1
        $x_1_3 = "WinHttpConnect" ascii //weight: 1
        $x_1_4 = "WinHttpOpenRequest" ascii //weight: 1
        $x_1_5 = "WinHttpReceiveResponse" ascii //weight: 1
        $x_1_6 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_PB_2147776586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.PB!MTB"
        threat_id = "2147776586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "S.%u.Passwords.txt" wide //weight: 1
        $x_1_2 = "S.%u.Cookies.txt" wide //weight: 1
        $x_1_3 = "GAME.Steam\\loginusers.vdf" wide //weight: 1
        $x_1_4 = "GAME.Steam\\config.vdf" wide //weight: 1
        $x_1_5 = "BTC.Wallet" wide //weight: 1
        $x_1_6 = "GAME.BattleNet" wide //weight: 1
        $x_1_7 = "PHOTO.WebCam.bmp" wide //weight: 1
        $x_1_8 = "S.Credentials.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_Spynoon_AV_2147778175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.AV!MTB"
        threat_id = "2147778175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LLD PDB" ascii //weight: 1
        $x_1_2 = {78 00 61 00 6d 00 70 00 70 00 5c 00 68 00 74 00 64 00 6f 00 63 00 73 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 72 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_3 = {78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 43 72 79 70 74 6f 72 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 4c 6f 61 64 65 72 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Spynoon_AV_2147778175_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.AV!MTB"
        threat_id = "2147778175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LLD PDB." ascii //weight: 1
        $x_1_2 = {43 00 3a 00 5c 00 78 00 61 00 6d 00 70 00 70 00 5c 00 68 00 74 00 64 00 6f 00 63 00 73 00 5c 00 43 00 72 00 79 00 70 00 74 00 6f 00 72 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 43 72 79 70 74 6f 72 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 4c 6f 61 64 65 72 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Spynoon_AVM_2147778563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.AVM!MTB"
        threat_id = "2147778563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hyvkfcorf" ascii //weight: 1
        $x_1_2 = "SHLWAPI.DLL" wide //weight: 1
        $x_1_3 = "141:1@1F1L1R1X1" ascii //weight: 1
        $x_1_4 = "1d1j1p1v1|1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_AVM_2147778563_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.AVM!MTB"
        threat_id = "2147778563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateFileW" ascii //weight: 1
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "DebugBreak" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "Hyvkfcorf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_AVM_2147778563_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.AVM!MTB"
        threat_id = "2147778563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HfkcdoekxlzOjbt" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "RpcMgmtInqComTimeout" ascii //weight: 1
        $x_1_4 = "RpcMgmtSetCancelTimeout" ascii //weight: 1
        $x_1_5 = "NdrConformantStructUnmarshall" ascii //weight: 1
        $x_1_6 = "RpcSmSetClientAllocFree" ascii //weight: 1
        $x_1_7 = "NdrByteCountPointerFree" ascii //weight: 1
        $x_1_8 = "NdrFullPointerXlatFree" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_AVM_2147778563_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.AVM!MTB"
        threat_id = "2147778563"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell_NotifyIcon" ascii //weight: 1
        $x_1_2 = "ExtractAssociatedIconExW" ascii //weight: 1
        $x_1_3 = "CursorLibLockStmt" ascii //weight: 1
        $x_1_4 = "CreateAntiMoniker" ascii //weight: 1
        $x_1_5 = "StgOpenStorageOnILockBytes" ascii //weight: 1
        $x_1_6 = "HMETAFILEPICT_UserMarshal" ascii //weight: 1
        $x_1_7 = "StgIsStorageILockBytes" ascii //weight: 1
        $x_1_8 = "RegisterDragDrop" ascii //weight: 1
        $x_1_9 = "rexec" ascii //weight: 1
        $x_1_10 = "NPLoadNameSpaces" ascii //weight: 1
        $x_1_11 = "rresvport" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_MFP_2147781040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.MFP!MTB"
        threat_id = "2147781040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Offline Keylogger Started" ascii //weight: 1
        $x_1_2 = "Online Keylogger Started" ascii //weight: 1
        $x_1_3 = "Remcos restarted by watchdog!" ascii //weight: 1
        $x_1_4 = "Uploading file to C&C:" ascii //weight: 1
        $x_1_5 = "Watchdog module activated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_MFP_2147781040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.MFP!MTB"
        threat_id = "2147781040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 14 0f 8a c1 02 ?? c0 c2 ?? 80 f2 ?? 2a ?? 04 ?? 88 04 ?? 41 3b}  //weight: 5, accuracy: Low
        $x_5_2 = {bc af 34 b0 6f 41 8f b6 7c c9 f9 a8 87 33 f1 42}  //weight: 5, accuracy: High
        $x_10_3 = {8b 45 f8 83 c0 ?? 89 45 ?? 8b 4d [0-10] 8b 55 f4 03 55 f8 8a 02 88 45 ?? 0f b6 4d ff [0-10] 83 f2 ?? 88 55 ?? 0f b6 45 ?? 2b 45 [0-10] c1 f9 [0-5] c1 e2 ?? 0b ca 88 4d ?? 0f b6 45 ?? f7 d0 [0-7] 83 e9 [0-8] c1 fa [0-5] c1 e0 ?? 0b d0 [0-10] 88 4d ?? 0f b6 55 ?? f7 da [0-10] 88 45 ?? 0f b6 4d ?? 33 4d ?? 88 4d ?? 0f b6 55 ?? 81 ea [0-4] 88 55 [0-5] c1 f8 [0-5] c1 e1 ?? 0b c1 [0-7] 83 ea [0-8] 83 f0 [0-10] 8a 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Spynoon_RTA_2147811334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RTA!MTB"
        threat_id = "2147811334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 ee d4 00 00 ba 86 21 01 00 4b 2d e9 5b 00 00 f7 d2 81 c1 9d 35 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {81 eb a8 07 00 00 b8 5b 71 00 00 f7 d3 81 fb d2 47 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RTA_2147811334_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RTA!MTB"
        threat_id = "2147811334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ltkbjqthwyl" ascii //weight: 1
        $x_1_2 = "uwfsecgx" ascii //weight: 1
        $x_1_3 = "poegcmkbaw" ascii //weight: 1
        $x_1_4 = "btgzlvbjss" ascii //weight: 1
        $x_1_5 = "roiclwghvv" ascii //weight: 1
        $x_1_6 = "cjqnxfogft" ascii //weight: 1
        $x_1_7 = "frzerxvgw" ascii //weight: 1
        $x_1_8 = "jofiqktddqk" ascii //weight: 1
        $x_1_9 = "miaxnjzzg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Spynoon_RTH_2147814079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RTH!MTB"
        threat_id = "2147814079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c1 92 ab 00 00 05 25 7f 00 00 48 f7 d3 81 e2 14 0c 01 00 f7 d1 58 b9 14 c4 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RTB_2147814080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RTB!MTB"
        threat_id = "2147814080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e3 de d1 00 00 5b 81 ea 19 f5 00 00 41 35 82 18 00 00 43 81 f9 c2 b4 00 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RMA_2147814277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RMA!MTB"
        threat_id = "2147814277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f6 1d 7e c4 b0 f7 de 81 c6 41 6b 9a 64 3b 73 ?? 0f 95 c1 89 8d ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 8b 0e 03 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RMA_2147814277_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RMA!MTB"
        threat_id = "2147814277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 00 ff ff ff 40 89 45 ?? 8b 45 ?? 0f b6 84 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 0f b6 09 33 c8 8b 45 ?? 03 45 ?? 88 08 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RM_2147815445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RM!MTB"
        threat_id = "2147815445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 e2 4b b6 00 00 43 ba 5f 7a 01 00 42 25 0e 23 01 00 05 09 f2 00 00 81 fa 2f e1 00 00 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RW_2147816372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RW!MTB"
        threat_id = "2147816372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 cd cc cc cc 83 c4 04 f7 e6 8b c6 c1 ea 03 8d 0c 92 03 c9 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 ff 07 3b f5 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RWA_2147816373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RWA!MTB"
        threat_id = "2147816373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 45 ?? 33 d2 b9 0a 00 00 00 f7 f1 0f b6 92 ?? ?? ?? ?? 8b 45 ?? 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 ?? 88 0a 8b 45 ?? 8b 08 83 c1 01 8b 55 ?? 89 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_RFB_2147816522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RFB!MTB"
        threat_id = "2147816522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 cd cc cc cc f7 e6 8b c6 c1 ea 03 68 ?? ?? ?? ?? 8d 0c 92 03 c9 2b c1 8a 80 ?? ?? ?? ?? 30 04 3e e8 ?? ?? ?? ?? 46 83 c4 04 3b f3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_DA_2147816637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.DA!MTB"
        threat_id = "2147816637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 d9 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 4d}  //weight: 2, accuracy: High
        $x_2_2 = "Hkcoedclxfkckdl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_DB_2147816638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.DB!MTB"
        threat_id = "2147816638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 0f f6 d0 32 c1 02 c1 f6 d0 02 c1 f6 d0 02 c1 d0 c8 02 c1 f6 d8 32 c1 f6 d0 2c ?? 88 04 0f 41 3b 4d fc 72 da}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 04 0f b2 ?? 04 ?? d0 c0 34 ?? 2a d0 32 d1 2a d1 c0 ca ?? f6 d2 c0 ca ?? 80 f2 ?? 80 ea ?? 80 f2 ?? f6 da c0 c2 ?? 80 c2 ?? 88 14 0f 41 3b 4d fc 72 cd}  //weight: 2, accuracy: Low
        $x_5_3 = "GFHFGHTRYRE" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Spynoon_RFA_2147816899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.RFA!MTB"
        threat_id = "2147816899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 e1 0f 00 00 00 81 c1 00 00 00 00 8a 14 08 88 55 ?? 8a 55 ?? 8b 45 ?? 8b 4d ?? 8b 75 ?? 89 34 24 89 4c 24 ?? 89 44 24 ?? 0f b6 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_MBZW_2147907374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.MBZW!MTB"
        threat_id = "2147907374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 eb fc 00 0f 20 00 33 44 54 65}  //weight: 1, accuracy: High
        $x_1_2 = {49 d8 46 00 6c 16 40 00 10 f0 30 00 00 ff ff ff 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Spynoon_AUFA_2147928078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spynoon.AUFA!MTB"
        threat_id = "2147928078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c3 c1 e8 05 89 45 fc 8b 45 e8 01 45 fc 8b cb c1 e1 04 03 4d ec 8d 14 1f 33 ca 33 4d fc 89 4d dc 8b 45 dc 29 45 f8 81 c7 47 86 c8 61 83 6d ?? 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

