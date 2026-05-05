rule Trojan_Win64_ValleyRat_ASD_2147929877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.ASD!MTB"
        threat_id = "2147929877"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {2b c8 b8 cd cc cc cc 41 f7 e2 80 c1 36 49 8d 43 01 41 30 4c 38 ff 45 33 db c1 ea 03 41 ff c2 8d 0c 92 03 c9 44 3b c9 4c 0f 45 d8}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_CZ_2147940457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.CZ!MTB"
        threat_id = "2147940457"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b c8 33 d2 49 8b c1 49 f7 70 10 8a 04 0a 43 30 04 19 49 ff c1 4d 3b ca 72 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_RY_2147942017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.RY!MTB"
        threat_id = "2147942017"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 14 0f 48 63 6c 24 ?? 48 69 dd ?? ?? ?? ?? 48 89 de 48 c1 ee ?? 48 c1 eb 20 01 f3 01 db 8d 1c 5b 29 dd 48 63 ed 32 94 2c ?? ?? ?? ?? 88 14 0f 8b 4c 24 ?? 83 c1 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_ETL_2147944051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.ETL!MTB"
        threat_id = "2147944051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b c0 4d 8d 49 01 99 41 ff c0 f7 f9 48 63 c2 0f b6 44 04 38 43 32 44 11 ff 42 88 84 0c 1f 05 00 00 41 81 f8 d8 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_AVER_2147945541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.AVER!MTB"
        threat_id = "2147945541"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 48 8b 44 24 20 b9 ?? ?? ?? ?? 48 f7 f1 48 8b c2 48 8d 0d ?? ?? ?? ?? 0f b6 04 01 48 8b 4c 24 28 0f be 09 33 c8 8b c1 48 8b 4c 24 28 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_PSG_2147947413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.PSG!MTB"
        threat_id = "2147947413"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 51 49 b9 3e b8 21 7f b3 89 2c a8 9c 41 c0 e1 14}  //weight: 5, accuracy: High
        $x_2_2 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 51 00 75 00 61 00 6c 00 63 00 6f 00 6d 00 6d 00}  //weight: 2, accuracy: Low
        $x_2_3 = {43 6f 6d 70 61 6e 79 4e 61 6d 65 ?? ?? ?? ?? 51 75 61 6c 63 6f 6d 6d}  //weight: 2, accuracy: Low
        $x_1_4 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 72 69 67 69 6e 61 6c 46 69 6c 65 6e 61 6d 65 ?? ?? 44 61 74 61 42 61 73 65 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_ValleyRat_TRK_2147950690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.TRK!MTB"
        threat_id = "2147950690"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.runService" ascii //weight: 1
        $x_1_2 = "main.decryptShellcode" ascii //weight: 1
        $x_1_3 = "main.installSelf" ascii //weight: 1
        $x_1_4 = "main.loadAndExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_CD_2147951223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.CD!MTB"
        threat_id = "2147951223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Virt" ascii //weight: 2
        $x_2_2 = {75 61 6c 41 c7 44 24 ?? 6c 6c 6f 63}  //weight: 2, accuracy: Low
        $x_3_3 = {ff d0 48 8b d8 48 85 c0 e9 ?? ?? ?? ?? 0f 84 20 00 00 00 41 b8 44 1d 02 00 66 ba 05 96 48 8d 15 ?? ?? ?? ?? 48 8b c8 e9 00 00 00 00 e8 ?? ?? ?? ?? ff d3 2b c0}  //weight: 3, accuracy: Low
        $x_2_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_BRS_2147951528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.BRS!MTB"
        threat_id = "2147951528"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 30 14 0e 48 83 c6 01 48 39 f2 75 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_AVYR_2147953089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.AVYR!MTB"
        threat_id = "2147953089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 01 c0 ff d0 48 8b 54 24 58 48 8b 8c 24 48 05 00 00 48 8b 05 81 1d 01 00 48 01 d0 31 d2 ff d0 48 8b 54 24 58 48 8b 8c 24 50 05 00 00 48 8b 05 96 1d 01 00 48 01 d0 ff d0 48 8b 54 24 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_GVC_2147956531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.GVC!MTB"
        threat_id = "2147956531"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 14 02 48 8b 44 24 60 88 54 04 53 48 ff c0 48 83 f8 05 7d 1d 48 89 44 24 60 b8 3e 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "main.ChaCha20Decrypt" ascii //weight: 1
        $x_1_3 = "ChaCha20Encrypted.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_PI_2147961039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.PI!MTB"
        threat_id = "2147961039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kiai360.bat" ascii //weight: 1
        $x_1_2 = "ZhiMaUpdate.dll" ascii //weight: 1
        $x_1_3 = "RedTeamKey123456" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_YAG_2147961044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.YAG!MTB"
        threat_id = "2147961044"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 44 24 30 8b 0c 24 48 8b 54 24 20 0f b6 0c 0a 33 c8 8b c1 8b 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_AD_2147961499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.AD!MTB"
        threat_id = "2147961499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasksbinPath=Programs//nologoGoStringunlinkatopenfdatFullPathn" ascii //weight: 1
        $x_1_2 = "main.setupAutoStart" ascii //weight: 1
        $x_1_3 = "main.setHidden" ascii //weight: 1
        $x_1_4 = "main.addScheduledTask" ascii //weight: 1
        $x_1_5 = "main.addRunOnce" ascii //weight: 1
        $x_1_6 = "main.addWinlogon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_AR_2147962925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.AR!AMTB"
        threat_id = "2147962925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Downloader" ascii //weight: 1
        $x_1_2 = "C:\\Users\\Public\\venwin.lock" ascii //weight: 1
        $x_1_3 = "[CmdHandler] monitor progress started." ascii //weight: 1
        $x_1_4 = "[CmdHandler] USDT hijack started successfully" ascii //weight: 1
        $x_1_5 = "[KeyboardRecord] Failed to enable offline keyboard" ascii //weight: 1
        $x_1_6 = "EnableOfflineKeyboard" ascii //weight: 1
        $x_1_7 = ".?AVKeyboardRecord@@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_YAH_2147963064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.YAH!MTB"
        threat_id = "2147963064"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 0c 04 02 0c 2c 0f b6 c9 8a 04 0c 42 32 04 07 43 88 04 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_XWB_2147964357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.XWB!MTB"
        threat_id = "2147964357"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Users\\Public\\venwin.lock" ascii //weight: 2
        $x_2_2 = "USDT hijack thread" ascii //weight: 2
        $x_1_3 = "\\venSuccess.ini" ascii //weight: 1
        $x_1_4 = "%ProgramData%\\Venlnk" ascii //weight: 1
        $x_1_5 = "BTC target address" ascii //weight: 1
        $x_1_6 = "ETH target address" ascii //weight: 1
        $x_2_7 = "EnableOfflineKeyboard" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_ABD_2147964463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.ABD!MTB"
        threat_id = "2147964463"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 c2 83 e2 07 0f b6 54 14 ?? 41 30 54 05 00 48 83 c0 01 48 39 f0}  //weight: 5, accuracy: Low
        $x_5_2 = {44 30 20 44 30 60 01 48 83 c0 02 49 39 c6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_ABVR_2147964647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.ABVR!MTB"
        threat_id = "2147964647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 68 74 74 70 73 3a 2f 2f 6b 64 64 69 31 32 2e 6f 73 73 2d 61 70 2d 73 6f 75 74 68 65 61 73 74 2d 31 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d 2f 75 70 6c 6f 61 64 73 2f 32 30 32 36 30 32 31 35 2f [0-15] 2e 65 78 65 20 2d 4f 75 74 46 69 6c 65 20 27 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 73 74 65 65 6d 65 2e 65 78 65 27 3b 20 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 73 74 65 65 6d 65 2e 65 78 65 27 22}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_AVY_2147966107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.AVY!MTB"
        threat_id = "2147966107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 84 24 b0 02 00 00 c6 44 24 20 57 c6 44 24 21 73 c6 44 24 22 32 c6 44 24 23 5f c6 44 24 24 33 c6 44 24 25 32 c6 44 24 26 2e c6 44 24 27 64 c6 44 24 28 6c c6 44 24 29 6c c6 44 24 2a 00 48 8d 4c 24 20 ff 94 24}  //weight: 2, accuracy: High
        $x_3_2 = "baidubai" ascii //weight: 3
        $x_4_3 = "111.170.150.47" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_AVY_2147966107_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.AVY!MTB"
        threat_id = "2147966107"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 c0 48 8d 15 5c 18 00 00 48 89 44 24 60 45 33 c9 48 8d 44 24 50 45 33 c0 48 89 44 24 48 33 c9 48 8d 45 a0 48 89 44 24 40 4c 89 74 24 38 4c 89 74 24 30}  //weight: 3, accuracy: High
        $x_2_2 = {4c 8d 8d 60 05 00 00 44 88 30 4c 8d 05 19 17 00 00 ba 04 01 00 00 48 8d 8d b0 0b 00 00 e8 ?? ?? ?? ?? 45 33 c9 c7 44 24 28 04 00 00 00 4c 8d 85 b0 0b 00 00 4c 89 74 24 20 48 8d 15 fe 16 00 00 33 c9}  //weight: 2, accuracy: Low
        $x_1_3 = "JavaLauncher" ascii //weight: 1
        $x_1_4 = "_Log.tmp" ascii //weight: 1
        $x_4_5 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\conf1.lnk" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_ValleyRat_SPKA_2147968503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ValleyRat.SPKA!MTB"
        threat_id = "2147968503"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ValleyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 45 f8 48 01 c8 44 31 c2 88 10 8b 45 28 01 45 20 8b 45 20 3b 45 30 7e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

