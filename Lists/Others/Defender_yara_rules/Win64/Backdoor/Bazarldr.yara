rule Backdoor_Win64_Bazarldr_MAK_2147775288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MAK!MTB"
        threat_id = "2147775288"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be c0 48 ff c1 03 d0 69 d2 [0-2] 00 00 8b c2 c1 f8 [0-1] 33 d0 8a 01 84 c0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 0c d2 8b c1 c1 f8 [0-1] 33 c1 69 c0 [0-2] 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MAK_2147775288_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MAK!MTB"
        threat_id = "2147775288"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c1 02 85 [0-4] 30 84 0d [0-4] 48 03 cf 48 83 f9 [0-1] 72}  //weight: 1, accuracy: Low
        $x_1_2 = {02 c8 30 4c 04 [0-1] 49 03 c6 48 83 f8 [0-1] 73 06 8a 4c 24 [0-1] eb}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 44 24 20 02 c1 30 44 0c [0-1] 49 03 ce 48 83 f9 [0-1] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_Bazarldr_MBK_2147775289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MBK!MTB"
        threat_id = "2147775289"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 f0 48 c1 f8 [0-1] 41 [0-4] 49 [0-3] 48 39 d3 0f 83 [0-4] 48 89 f0 48 c1 f8 [0-1] 41 01 49 02 48 39 d3 0f 83 [0-4] 48 89 f0 48 83 c6 [0-1] 48 c1 f8 [0-1] 41 01 48 83 c3 [0-1] 48 39 df 0f 8e [0-4] 49 02 48 39 d3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MBK_2147775289_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MBK!MTB"
        threat_id = "2147775289"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be f3 01 fe 89 f3 c1 e3 [0-1] 01 f3 89 df c1 ff [0-1] 31 df 0f b6 5d 00 48 83 c5 01 84 db 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be f3 01 ee 89 f3 c1 e3 [0-1] 01 f3 89 dd c1 fd [0-1] 31 dd 0f b6 19 48 83 c1 01 84 db 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 6c ed 00 89 e9 c1 f9 [0-1] 31 e9 89 ce c1 e6 [0-1] 01 ce 81 fe [0-4] 74 [0-1] 48 83 c7 01 4c 39 ff 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_Bazarldr_MDK_2147775319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MDK!MTB"
        threat_id = "2147775319"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 fe f7 d6 81 e6 [0-4] 89 fb 21 eb 09 f3 31 eb 81 e7 [0-4] 09 df 89 bc 84 [0-4] 48 ff c1 48 ff c0 48 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 84 2c 89 ca 44 31 fa 21 ca 31 f9 44 21 f9 89 ce 21 d6 31 ca 09 f2 89 d1 31 f9 81 e1 [0-4] 81 e2 [0-4] 09 ca 89 54 [0-2] 48 ff c0 48 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_3 = {89 d6 31 fe 89 f5 81 cd [0-4] 89 d3 81 cb [0-4] 44 21 f3 81 e6 [0-4] 09 de 44 21 f5 81 e2 [0-4] 09 ea 31 f2 89 d5 31 fd 81 e5 [0-4] 81 e2 [0-4] 09 ea 89 [0-3] 4c 01 e1 4c 89 e2 48 29 ca 4c 01 ea 48 f7 da 4a 8d 0c 2a 48 ff c1 48 ff c0 48 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_Bazarldr_MK_2147775422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MK!MTB"
        threat_id = "2147775422"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d0 89 d0 44 31 f8 25 [0-4] bd [0-4] 21 ea 09 c2 89 d0 31 e8 83 e0 fe 81 f2 [0-4] 09 c2 44 39 fa 0f 94 c0 0f 95 c2 83 f9 [0-1] 0f 9c c3 83 f9 [0-1] 0f 9f c1 20 c8 08 d1 20 d3 08 c3 89 c8 30 d8 b8 [0-4] ba [0-4] 0f 45 c2 84 db 89 c5 ba [0-4] 0f 45 ea 48 89 74 24 70 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MK_2147775422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MK!MTB"
        threat_id = "2147775422"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 20 44 8b cb 44 8b c0 33 c9 ff 15 [0-4] 48 8b d8 44 8b 44 24 [0-1] 48 8b d7 48 8b c8 e8 [0-3] 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-1] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4}  //weight: 1, accuracy: Low
        $x_1_3 = {41 0f b6 00 48 ff c1 49 ff c8 48 3b cb 42 88 44 21 [0-1] 7c ec}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 06 48 8b 4c 24 [0-1] 45 33 c9 89 44 24 [0-1] 45 8d 41 [0-1] 33 d2 48 89 74 24 [0-1] 48 89 6c 24 [0-1] ff 15 [0-4] 85 c0 0f 95 c0 eb bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win64_Bazarldr_MFK_2147775750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MFK!MTB"
        threat_id = "2147775750"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 60 41 b9 [0-4] 44 8b c0 33 c9 ff 15 [0-4] 48 8b f8 44 8b 44 24 [0-1] 48 8b d6 48 8b c8 e8 [0-3] 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-1] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 06 48 8b 4c 24 [0-1] 45 33 c9 89 44 24 [0-1] 45 8d 41 [0-1] 33 d2 48 89 74 24 [0-1] 48 89 6c 24 [0-1] ff 15 [0-4] 85 c0 0f 95 c0 eb bd}  //weight: 1, accuracy: Low
        $x_1_4 = "mgzJg#<Xgl0A!i+" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MGK_2147775812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MGK!MTB"
        threat_id = "2147775812"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 11 b8 [0-4] 2b c2 44 6b c0 [0-1] 41 8b c3 41 f7 e8 41 03 d0 c1 fa [0-1] 8b c2 c1 e8 [0-1] 03 d0 6b c2 [0-1] 44 2b c0 41 8b c3 41 83 c0 04 41 f7 e8 41 03 d0 c1 fa 02 8b c2 c1 e8 03 03 d0 6b c2 04 44 2b c0 45 88 01 49 ff c1 49 83 ea 01 75}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 11 b8 [0-4] 2b c2 44 8d 04 c0 41 8b c3 41 c1 e0 [0-1] 41 f7 e8 41 03 d0 c1 fa [0-1] 8b c2 c1 e8 [0-1] 03 d0 6b c2 [0-1] 44 2b c0 41 8b c3 41 83 c0 04 41 f7 e8 41 03 d0 c1 fa 02 8b c2 c1 e8 03 03 d0 6b c2 04 44 2b c0 45 88 01 49 ff c1 49 83 ea 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MHK_2147775856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MHK!MTB"
        threat_id = "2147775856"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 20 44 8b cf 44 8b c0 33 c9 ff 15 [0-4] 48 8b f8 44 8b 44 24 [0-1] 48 8b d6 48 8b c8 e8 [0-3] 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-1] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4}  //weight: 1, accuracy: Low
        $x_1_3 = {41 8a 00 48 ff c2 49 ff c8 48 3b d3 42 88 44 32 [0-1] 7c ed}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 06 48 8b 4c 24 [0-1] 45 33 c9 89 44 24 [0-1] 45 8d 41 [0-1] 33 d2 48 89 74 24 [0-1] 48 89 6c 24 [0-1] ff 15 [0-4] 85 c0 0f 95 c0 eb 02}  //weight: 1, accuracy: Low
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_6 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 4e 65 74 77 6f 72 6b [0-16] 4e 6f 45 6e 74 69 72 65 4e 65 74 77 6f 72 6b}  //weight: 1, accuracy: Low
        $x_1_7 = "CLSID\\%1\\InProcServer32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win64_Bazarldr_MJK_2147775971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MJK!MTB"
        threat_id = "2147775971"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 74 24 20 b8 6b 00 00 00 66 89 44 24 40 b9 65 00 00 00 66 89 4c 24 42 b8 72 00 00 00 66 89 44 24 44 b8 6e 00 00 00 66 89 44 24 46 66 89 4c 24 48 b9 6c 00 00 00 66 89 4c 24 4a b8 33 00 00 00 66 89 44 24 4c b8 32 00 00 00 66 89 44 24 4e b8 2e 00 00 00 66 89 44 24 50 b8 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 54 24 20 44 8b cb 44 8b c0 33 c9 ff 15 [0-4] 48 8b d8 44 8b 44 24 [0-1] 48 8b d7 48 8b c8 e8 [0-3] 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-1] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4}  //weight: 1, accuracy: Low
        $x_1_4 = {41 0f b6 00 48 ff c1 49 ff c8 48 3b cb 42 88 44 21 [0-1] 7c ec}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 06 48 8b 4c 24 [0-1] 45 33 c9 89 44 24 [0-1] 45 8d 41 [0-1] 33 d2 48 89 74 24 [0-1] 48 89 6c 24 [0-1] ff 15 [0-4] 85 c0 0f 95 c0 eb bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win64_Bazarldr_DB_2147776086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.DB!MTB"
        threat_id = "2147776086"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "37"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "PDH Counter Statistics Demonstration Application" ascii //weight: 10
        $x_10_2 = "pdh.dll" ascii //weight: 10
        $x_10_3 = "Statlist" ascii //weight: 10
        $x_1_4 = "PdhComputeCounterStatistics" ascii //weight: 1
        $x_1_5 = "PdhCollectQueryData" ascii //weight: 1
        $x_1_6 = "PostQuitMessage" ascii //weight: 1
        $x_1_7 = "DispatchMessageA" ascii //weight: 1
        $x_1_8 = "GetTickCount" ascii //weight: 1
        $x_1_9 = "ClientToScreen" ascii //weight: 1
        $x_1_10 = "WriteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_DC_2147776087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.DC!MTB"
        threat_id = "2147776087"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "\\AutoCB\\Release\\AutoCB.pdb" ascii //weight: 20
        $x_20_2 = "AutoCB MFC Application" ascii //weight: 20
        $x_1_3 = "IsClipboardFormatAvailable" ascii //weight: 1
        $x_1_4 = "GetTempFileNameA" ascii //weight: 1
        $x_1_5 = "LockResource" ascii //weight: 1
        $x_1_6 = "GetDiskFreeSpaceA" ascii //weight: 1
        $x_1_7 = "CopyFileA" ascii //weight: 1
        $x_1_8 = "DeleteFileA" ascii //weight: 1
        $x_1_9 = "WriteFile" ascii //weight: 1
        $x_1_10 = "LockFile" ascii //weight: 1
        $x_1_11 = "SetEndOfFile" ascii //weight: 1
        $x_1_12 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_13 = "PostMessageA" ascii //weight: 1
        $x_1_14 = "SetCapture" ascii //weight: 1
        $x_1_15 = "KillTimer" ascii //weight: 1
        $x_1_16 = "CryptEncrypt" ascii //weight: 1
        $x_1_17 = "GetDesktopWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MLK_2147776216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MLK!MTB"
        threat_id = "2147776216"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 20 44 8b cb 44 8b c0 33 c9 ff 15 [0-4] 48 8b d8 44 8b 44 24 [0-1] 48 8b d7 48 8b c8 e8 [0-3] 00}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-1] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4}  //weight: 1, accuracy: Low
        $x_1_3 = {41 0f b6 00 48 ff c1 49 ff c8 48 3b cb 42 88 44 21 [0-1] 7c ec}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 06 48 8b 4c 24 [0-1] 45 33 c9 89 44 24 [0-1] 45 8d 41 [0-1] 33 d2 48 89 74 24 [0-1] 48 89 6c 24 [0-1] ff 15 [0-4] 85 c0 0f 95 c0 eb bd}  //weight: 1, accuracy: Low
        $x_1_5 = "e:\\malta\\richeditgrid_src(1)\\Release\\RichEditGrid.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win64_Bazarldr_MNK_2147776220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MNK!MTB"
        threat_id = "2147776220"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 0a 1a 00 00 41 b8 0b 00 00 00 48 8d 0d 7a b2 ff ff ff 15 [0-4] 48 8b f8 48 8b d0 48 8d 0d 67 b2 ff ff ff 15 [0-4] 48 8b f0 48 8b d7 48 8d 0d 54 b2 ff ff ff 15 [0-4] 89 44 24 50}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d0 33 c9 44 8d 49 [0-1] 41 b8 [0-2] 00 00 ff 15 [0-4] 48 8b f8 44 8b 44 24 50 48 8b d6 48 8b c8 e8 [0-3] 00}  //weight: 1, accuracy: Low
        $x_1_3 = {48 8b 44 0a f8 4c 8b 54 0a f0 48 83 e9 [0-1] 48 89 41 18 4c 89 51 10 48 8b 44 0a 08 4c 8b 14 0a 49 ff c9 48 89 41 08 4c 89 11 75 d5}  //weight: 1, accuracy: Low
        $x_1_4 = {41 8a 00 48 ff c2 49 ff c8 48 3b d3 42 88 44 32 [0-1] 7c ed}  //weight: 1, accuracy: Low
        $x_1_5 = {48 8b 4c 24 50 45 33 c9 89 44 24 30 45 8d 41 01 33 d2 48 89 74 24 28 48 89 6c 24 20 ff 15 [0-4] 85 c0 0f 95 c0 eb 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win64_Bazarldr_MOK_2147776318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MOK!MTB"
        threat_id = "2147776318"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 8b f8 48 8b f2 48 8b e9 ff 15 [0-4] 48 85 c0 75 04 33 c0 eb 4b 48 8b c8 ff 15 [0-4] 48 8b d8 48 85 c0 74 eb 48 8b d6 48 8b cd ff 15 [0-4] 44 8b d8 4c 03 db 83 e7 0f 76}  //weight: 10, accuracy: Low
        $x_10_2 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-1] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4}  //weight: 10, accuracy: Low
        $x_10_3 = {41 8a 00 48 ff c2 49 ff c8 48 3b d7 88 44 2a [0-1] 7c}  //weight: 10, accuracy: Low
        $x_1_4 = "ESET hyunya" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" ascii //weight: 1
        $x_1_6 = "%s%s.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MPK_2147778715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MPK!MTB"
        threat_id = "2147778715"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 0a b8 [0-4] 83 e9 [0-1] 44 6b c1 [0-1] 41 f7 e8 41 03 d0 c1 fa [0-1] 8b c2 c1 e8 [0-1] 03 d0 6b c2 [0-1] 44 2b c0 b8 00 41 83 c0 05 41 f7 e8 41 03 d0 c1 fa 03 8b c2 c1 e8 04 03 d0 6b c2 05 44 2b c0 45 88 02 49 ff c2 49 83 eb 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MQK_2147780378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MQK!MTB"
        threat_id = "2147780378"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 24 99 41 f7 7e [0-1] 48 8b 07 48 63 4c 24 [0-1] 8a 04 08 49 8b 36 48 63 d2 8a 1c 16 89 da 44 30 ca 20 c2 44 30 c8 20 d8 08 d0 48 8b 54 24 [0-1] 48 8b 12 88 04 0a 8b 44 24 [0-1] ff c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Bazarldr_MRK_2147781102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarldr.MRK!MTB"
        threat_id = "2147781102"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 c1 e9 20 01 d1 83 c1 [0-1] 89 ce c1 ee [0-1] c1 f9 06 01 f1 89 ce c1 e6 07 29 f1 01 d1 83 c1 00 88 4c 04 [0-1] 48 ff c0 48 83 f8 [0-1] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

