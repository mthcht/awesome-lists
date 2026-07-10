rule Trojan_Win64_ValleyRAT_PAHM_2147947493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.PAHM!MTB"
        threat_id = "2147947493"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8d 4c 24 40 ?? ?? 48 8b 44 24 40 48 2b 44 24 30 0f 57 c9 f2 48 0f 2a c8 0f 57 c0 f2 48 0f 2a 44 24 38 f2 0f 5e c8 66 0f 2f f1}  //weight: 2, accuracy: Low
        $x_2_2 = {48 8b 44 24 48 48 2b 44 24 30 0f 57 c9 f2 48 0f 2a c8 0f 57 c0 f2 48 0f 2a 44 24 38 f2 0f 5e c8 f2 ?? ?? ?? ?? ?? ?? ?? f2 0f 2c c1 3d 88 13 00 00 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_TBK_2147948769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.TBK!MTB"
        threat_id = "2147948769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yehbe253" ascii //weight: 1
        $x_1_2 = "\\Telegram.lnk" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Public\\Desktop\\QQ.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_ABK_2147948770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ABK!MTB"
        threat_id = "2147948770"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 10 04 02 66 0f ef c1 0f 11 04 02 0f ?? 44 02 10 66 0f ef c1 0f 11 44 02 ?? 83 c0 ?? 3b c6 72}  //weight: 2, accuracy: Low
        $x_2_2 = {80 34 10 58 40 3b c1 72}  //weight: 2, accuracy: High
        $x_2_3 = "xyz/" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_CBK_2147955196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.CBK!MTB"
        threat_id = "2147955196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d1 d3 e8 89 c1 48 8b 44 24 ?? 33 08 89 08 48 8b 44 24 ?? 48 83 c0 01 48 89 44 24}  //weight: 2, accuracy: Low
        $x_2_2 = {d3 e0 89 c0 48 31 c2 48 8b 44 24 ?? 8b 08 48 01 d1 89 08 48 8b 44 24 ?? 48 83 c0 ?? 48 89 44 24 ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_BA_2147957459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.BA!MTB"
        threat_id = "2147957459"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 20 ff c0 89 44 24 20 83 7c 24 20 40 ?? ?? 48 63 44 24 20 0f b6 44 04 50 83 f0 ?? 48 63 4c 24 20 88 44 0c 50 48 63 44 24 20 0f b6 84 04 ?? ?? ?? ?? 83 f0 5c 48 63 4c 24 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_NW_2147958301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.NW!MTB"
        threat_id = "2147958301"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 54 24 ?? 0f b6 04 02 33 c1 48 63 4c 24 ?? 48 8b 54 24 ?? 48 ff ca 48 6b d2 ?? 48 03 4c 24 ?? 88 04 11 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_AMV_2147959006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.AMV!MTB"
        threat_id = "2147959006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 8b c8 49 f7 e0 49 8b c0 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 17 48 2b c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 41 30 04 18 49 ff c0 4c 3b c5 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_GDZ_2147959085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.GDZ!MTB"
        threat_id = "2147959085"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ba 04 01 00 00 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 8d 15 fc 22 00 00 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 8d 4c 24 20 ff 15 ?? ?? ?? ?? 48 89 05 47 46 00 00 48 85 c0 0f 84 ?? ?? ?? ?? 48 8d 15 e7 22 00 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8b 0d 27 46 00 00 48 8d 15 e0 22 00 00 48 89 05 f9 45 00 00 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = "\\_\\_\\document.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_PAHN_2147961960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.PAHN!MTB"
        threat_id = "2147961960"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 74 48 8b 45 00 48 01 d0 0f b6 00 8b 4d 74 48 8b 55 00 48 01 ca 32 45 7b 88 02 0f b6 45 fe 00 45 7b 83 45 74 01 8b 45 74 3b 45 14 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_LM_2147962903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.LM!MTB"
        threat_id = "2147962903"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 8b 43 10 48 ff c7 80 74 07 ff 22 48 ff c9}  //weight: 20, accuracy: High
        $x_10_2 = {c7 85 a0 04 00 00 57 72 69 74 c7 85 a4 04 00 00 65 50 72 6f c7 85 a8 04 00 00 63 65 73 73 c7 85 ac 04 00 00 4d 65 6d 6f 66 c7 85 b0 04 00 00 72 79}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_ARA_2147963820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ARA!MTB"
        threat_id = "2147963820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 0f b6 84 22 90 af 01 00 30 04 31 48 ff c1 eb da}  //weight: 2, accuracy: High
        $x_2_2 = {48 8b c1 83 e0 0f 42 02 94 20 60 1a 00 00 80 f2 aa 80 ea 55 88 94 0c 20 06 00 00 48 ff c1 eb c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_ARA_2147963820_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ARA!MTB"
        threat_id = "2147963820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c7 45 bc 63 00 2f 00 c7 45 c0 44 00 6f 00 c7 45 c4 77 00 6e 00 c7 45 c8 6c 00 6f 00 c7 45 cc 61 00 64 00 c7 45 d0 73 00 2f 00 c7 45 d4 31 00 2e 00 c7 45 d8 62 00 69 00 c7 45 dc 6e 00 00 00 e8 45 2c 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_PGVA_2147964550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.PGVA!MTB"
        threat_id = "2147964550"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 8b 7c 24 78 49 31 f1 49 c1 c9 18 4d 01 ca 4c 89 94 24 38 01 00 00 49 31 ca 48 8d 0c 2f 49 c1 ca 10 4c 01 c1 4c 01 d6 4c 89 94 24 90 01 00 00 48 89 b4 24 88 01 00 00 48 31 ca 4c 31 ce}  //weight: 5, accuracy: High
        $x_5_2 = {f3 0f 6f 00 48 83 c2 10 66 0f ef 42 f0 48 83 c0 10 66 0f ef 42 30 0f 11 40 f0 48 39 d1 75 e1}  //weight: 5, accuracy: High
        $x_5_3 = {48 89 c2 83 e2 07 0f b6 54 14 [0-2] 30 54 05 00 48 83 c0 01 [0-1] 39 [0-1] 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ValleyRAT_ABMV_2147964912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ABMV!MTB"
        threat_id = "2147964912"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 d2 48 8b c1 49 f7 f0 42 0f b6 04 0a 30 04 19 48 ff c1 48 3b ce 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_ABWV_2147965105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ABWV!MTB"
        threat_id = "2147965105"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 d1 48 89 d0 83 e0 1f 83 e1 0f 41 8a 0c 08 41 32 0c 01 89 d0 41 32 0c 12 41 0f af c3 83 c0 0d 31 c8 88 04 16 48 ff c2 eb d0}  //weight: 5, accuracy: High
        $x_2_2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 46 00 20 00 2f 00 54 00 4e 00 20 00 22 00 [0-11] 22 00 20 00 2f 00 54 00 52 00 20 00 22 00 22 00 25 00 73 00 22 00 22 00 20 00 2f 00 53 00 43 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00}  //weight: 2, accuracy: Low
        $x_2_3 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 20 2f 46 20 2f 54 4e 20 22 [0-11] 22 20 2f 54 52 20 22 22 25 73 22 22 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 52 4c 20 48 49 47 48 45 53 54}  //weight: 2, accuracy: Low
        $x_1_4 = "Debugger detected" ascii //weight: 1
        $x_1_5 = "Task persistence added" ascii //weight: 1
        $x_1_6 = "XOR Decrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ValleyRAT_ABVS_2147966047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ABVS!MTB"
        threat_id = "2147966047"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 49 8b c2 49 f7 f1 42 8a 04 02 41 30 04 0a 49 ff c2 4d 3b d3 72}  //weight: 5, accuracy: High
        $x_1_2 = "CreateStealthShortcut" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "PersistFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_LR_2147967096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.LR!MTB"
        threat_id = "2147967096"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {4c 89 b4 24 e8 04 00 00 4c 89 bc 24 e0 04 00 00 c7 85 70 02 00 00 68 00 74 00 c7 85 74 02 00 00 74 00 70 00 c7 85 78 02 00 00 3a 00 2f 00 c7 85 7c 02 00 00 2f 00 32 00 c7 85 80 02 00 00 33 00 2e 00 c7 85 84 02 00 00 32 00 32 00 c7 85 88 02 00 00 36 00 2e 00 c7 85 8c 02 00 00 35 00 37 00 c7 85 90 02 00 00 2e 00 36 00 c7 85 94 02 00 00 39 00 3a 00 c7 85 98 02 00 00 37 00 37 00 c7 85 9c 02 00 00 38 00 39 00 c7 85 a0 02 00 00 2f 00 70 00 c7 85 a4 02 00 00 6f 00 63 00 c7 85 a8 02 00 00 6b 00 65 00}  //weight: 20, accuracy: High
        $x_1_2 = "URLDownloadToFileW" ascii //weight: 1
        $x_2_3 = "IsDebuggerPresent" ascii //weight: 2
        $x_4_4 = "CreateToolhelp32Snapshot" ascii //weight: 4
        $x_5_5 = "SetUnhandledExceptionFilter" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_LRA_2147967100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.LRA!MTB"
        threat_id = "2147967100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {c7 45 64 6f 00 63 00 c7 45 68 6b 00 65 00 c7 45 6c 74 00 2e 00 c7 45 70 65 00 78 00 c7 45 74 65 00 00 00 c7 85 80 00 00 00 43 00 3a 00 c7 85 84 00 00 00 2f 00 55 00 c7 85 88 00 00 00 73 00 65 00 c7 85 8c 00 00 00 72 00 73 00 c7 85 90 00 00 00 2f 00 50 00 c7 85 94 00 00 00 75 00 62 00 c7 85 98 00 00 00 6c 00 69 00 c7 85 9c 00 00 00 63 00 2f 00 c7 85 a0 00 00 00 44 00 6f 00 c7 85 a4 00 00 00 77 00 6e 00 c7 85 a8 00 00 00 6c 00 6f 00 c7 85 ac 00 00 00 61 00 64 00 c7 85 b0 00 00 00 73 00 2f 00}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_AR_2147967518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.AR!MTB"
        threat_id = "2147967518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 8b c3 0f 1f 40 00 45 30 08 49 ff c0 8b 05 ?? ?? ?? ?? 49 8b c8 48 2b cb 41 80 c1 ?? 48 3b c8 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_ZNE_2147967578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ZNE!MTB"
        threat_id = "2147967578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 30 02 48 ff c2 44 8b 0d ?? ?? ?? ?? 48 8b ca 49 2b cf 41 80 c0 ?? 49 3b c9 72}  //weight: 5, accuracy: Low
        $x_5_2 = {32 d2 c0 e1 04 41 ff c1 0a ca 41 88 4d 00 49 ff c5 49 ff c0 49 ff c0 4d 3b c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_ABRS_2147967643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.ABRS!MTB"
        threat_id = "2147967643"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 49 8b c2 49 f7 f1 42 8a 04 02 41 30 04 0a 49 ff c2 4d 3b d3 72 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_NV_2147969427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.NV!MTB"
        threat_id = "2147969427"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 12 48 89 c1 ff d2 84 c0 74 35 48 8b 45 10 48 83 c0 08 48 89 c1 e8 65 6a 00 00 84 c0 74 55 48 8b 45 10 48 83 c0 08 48 89 c1 e8 81 6a 00 00 48 8b 10 48 83 c2 10 48 8b 12 48 89 c1 ff d2 eb 34 48 8b 45 10 48 83 c0 10 48 89 c1}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 10 c7 45 fc ?? 01 00 00 8b 4d fc 48 8b 45 10 48 8b 40 08 48 8b 55 10 48 8b 52 08 8b 12 31 ca 89 10 b8 00 00 00 00 85 c0 74 0a 48 8b 4d 10 e8 84 a5 03 00}  //weight: 2, accuracy: Low
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "Application Data\\Microsoft\\EdgeUpdate" ascii //weight: 1
        $x_1_5 = "index_jisu_1.0.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_AHB_2147969438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.AHB!MTB"
        threat_id = "2147969438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {f3 42 0f 6f 04 30 0f 57 c1 f3 0f 7f 04 18 8d 42 ?? 83 c2 ?? f3 42 0f 6f 04 30 0f 57 c1 f3 0f 7f 04 18 45 3b c1 72}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_SPK_2147971016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.SPK!MTB"
        threat_id = "2147971016"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 48 8b 4d f0 48 01 c1 48 89 4d e0 0f b6 09 0f b6 45 eb 31 c1 48 8b 45 e0 88 08 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_KK_2147971558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.KK!MTB"
        threat_id = "2147971558"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\DisplaySessionContainers.log" ascii //weight: 10
        $x_5_2 = "C:\\ProgramLog\\Windows\\AppData\\Local\\Microsoft\\Log\\TGFile.exe" ascii //weight: 5
        $x_3_3 = "~p1:203.91.74.177~o1:6677~t1:1" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_PAHR_2147972668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.PAHR!MTB"
        threat_id = "2147972668"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 44 24 60 80 b4 05 ?? ?? 00 00 09 8b 44 24 60 03 c6 89 44 24 60 8b 44 24 60 83 f8 ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_PAHS_2147972669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.PAHS!MTB"
        threat_id = "2147972669"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 42 8a 04 10 32 04 13 88 02 8d 41 01 48 ff c2 83 f8 ?? 1b c9 23 c8 49 83 e8 01 75 e2}  //weight: 5, accuracy: Low
        $x_5_2 = {41 8b c0 8a 04 ?? 41 32 04 0a 88 01 41 8d 40 01 48 ff c1 3b c6 45 1b c0 44 23 c0 49 83 eb 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_ValleyRAT_LRB_2147972729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.LRB!MTB"
        threat_id = "2147972729"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8b 84 8d 20 ff ff ff 31 84 8d 24 ff ff ff 41 3b ce}  //weight: 20, accuracy: High
        $x_10_2 = {c1 e0 10 0b c8 0f b6 7a 0f 0f b6 42 02 c1 e0 08 0b c8 89 7d e4 0f b6 42 03 0b c8 0f b6 42 05 33 8d f8 fc ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_PAHT_2147972979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.PAHT!MTB"
        threat_id = "2147972979"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 48 8d 52 01 [0-1] 0f b6 04 ?? 41 32 44 ?? ff 88 42 ff 8d 41 01 83 f8 20 41 8b ce 0f 42 c8 ?? 83 ?? 01 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRAT_AAVR_2147973335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRAT.AAVR!MTB"
        threat_id = "2147973335"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b c2 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 42 0f b6 04 19 41 30 40 ?? 49 83 e9 01 0f 85 77 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

