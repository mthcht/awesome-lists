rule Trojan_Win64_RustyStealer_A_2147912272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.A!MTB"
        threat_id = "2147912272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 c1 f7 d0 41 89 c7 41 21 cf 66 0f bc c0 0f b7 c0 48 c1 e0 05 48 89 fe 48 29 c6 48 8b 56 f0 4c 8b 46 f8}  //weight: 1, accuracy: High
        $x_1_2 = "encryptedPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_ZX_2147913787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.ZX!MTB"
        threat_id = "2147913787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 89 e0 45 21 d8 42 33 3c 82 33 79 e8 45 89 e0 41 c1 e8 18 45 89 f1 41 c1 e9 10 45 21 d9 46 8b 3c 8e 47 33 3c 82 41 89 e8 41 c1 e8 08 45 21 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_GPXB_2147938495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.GPXB!MTB"
        threat_id = "2147938495"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Prysmax Stealer Cookies" ascii //weight: 2
        $x_2_2 = "Windows DefenderC:\\Program Files\\Windows DefenderKasperskyC:\\Program Files (x86)\\Kaspersky LabAvast" ascii //weight: 2
        $x_1_3 = "LOCALAPPDATAsrc/modules/cookies.rs" ascii //weight: 1
        $x_1_4 = "chromeGoogle\\Chrome\\Application\\chrome.exeGoogle\\Chrome\\User Dataedge" ascii //weight: 1
        $x_1_5 = "schtasks/Delete/TN/Create/SC/RLHIGHEST/RUNT AUTHORITY\\SYSTEM/TR[CLIPPER]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_RCB_2147938566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.RCB!MTB"
        threat_id = "2147938566"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 39 d5 0f 83 fe 00 00 00 49 83 fd 40 0f 83 e8 00 00 00 42 32 34 28 42 88 b4 2c c0 01 00 00 eb ac}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_MMR_2147939052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.MMR!MTB"
        threat_id = "2147939052"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd/C96.9.125.200" ascii //weight: 1
        $x_1_2 = "Users\\Public\\Libraries\\systemhelper.exe" ascii //weight: 1
        $x_1_3 = "revshell.pdb" ascii //weight: 1
        $x_1_4 = "RustBacktraceMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_SMW_2147941644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.SMW!MTB"
        threat_id = "2147941644"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 44 11 08 4c 33 44 08 08 4c 89 84 0d 48 24 00 00 48 83 c1 08 48 83 f9 50 72 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_IDK_2147948755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.IDK!MTB"
        threat_id = "2147948755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set-MpPreference -DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_2 = "DontStopIfGoingOnBatteries" ascii //weight: 1
        $x_1_3 = "Telegram notification sent successfully" ascii //weight: 1
        $x_1_4 = "Payload execution failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_GXL_2147956082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.GXL!MTB"
        threat_id = "2147956082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discord_control.pdb" ascii //weight: 1
        $x_1_2 = "missionsL3B" ascii //weight: 1
        $x_1_3 = "reactionuespemosarenegylmodnarodsetybdet" ascii //weight: 1
        $x_1_4 = "idalert_system_mesrule_trigger" ascii //weight: 1
        $x_1_5 = "Asec-websocket-vesec-websocket-kebsocket-protocolsec" ascii //weight: 1
        $x_1_6 = "GetAdaptersAddresses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_PB_2147956812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.PB!MTB"
        threat_id = "2147956812"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rust_stealer_xss.pdb" ascii //weight: 5
        $x_2_2 = "Chromium7StarAmigoBrave-BrowserBraveSoftwareCentBrowserChedotChrome SxSGoogleBrowserCocCocDragonComodo" ascii //weight: 2
        $x_2_3 = "Epic Privacy BrowserChromeKometaOrbitumSputnikTorchUranuCozMediaVivaldiAtomMail.RuOpera" ascii //weight: 2
        $x_2_4 = "SoftwareOpera StableOpera GX StableMappleStudioChromePlusIridiumsleipnir5settingsCatalinaGroupCitrioCoowooliebaoQip Surf360Browser" ascii //weight: 2
        $x_2_5 = "encryptedUsernamencryptedPasswore" ascii //weight: 2
        $x_2_6 = "src\\chromium\\decryption_core.rs" ascii //weight: 2
        $x_2_7 = "LOCALAPPDATAsrc\\chromium\\dumper.rs" ascii //weight: 2
        $x_1_8 = "APPDATAsrc\\firefox\\firefox.rs" ascii //weight: 1
        $x_1_9 = "src\\messengers\\skype.rs" ascii //weight: 1
        $x_1_10 = "src\\messengers\\telegram.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_NSA_2147961155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.NSA!MTB"
        threat_id = "2147961155"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "McAfeeMcAfee\\Endpoint Security" ascii //weight: 1
        $x_1_2 = "Panda SecurityPandaPanda Security\\Protection" ascii //weight: 1
        $x_1_3 = "CylanceCylancePROTECTCylance\\Desktop" ascii //weight: 1
        $x_1_4 = "ESETESET SecurityESET\\ESET SecurityESET\\ESET Endpoint Security" ascii //weight: 1
        $x_1_5 = "AvastAvast AntivirusAVAST Software\\AvastAVAST Software\\Persistent Data\\Avast\\avast5.ini" ascii //weight: 1
        $x_2_6 = "No detections foundPROGRAMDATAC:\\ProgramData" ascii //weight: 2
        $x_1_7 = "MalwarebytesMalwarebytes\\MBAMService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_A_2147962353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.A!AMTB"
        threat_id = "2147962353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "src\\modules\\persist.rs" ascii //weight: 2
        $x_2_2 = "src\\modules\\interface.rs" ascii //weight: 2
        $x_1_3 = "src\\modules\\detect_av.rsh" ascii //weight: 1
        $x_1_4 = "No detections found" ascii //weight: 1
        $x_1_5 = "stable-x86_64-pc-windows-msvc" ascii //weight: 1
        $x_1_6 = "ESETESET SecurityESET\\ESET SecurityESET\\ESET Endpoint Security" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_RustyStealer_AH_2147964911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.AH!MTB"
        threat_id = "2147964911"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Simple stub started at" ascii //weight: 10
        $x_20_2 = "Payload read successfully, size:" ascii //weight: 20
        $x_30_3 = "C:\\temp\\debug_simple.txt" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_GXH_2147965873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.GXH!MTB"
        threat_id = "2147965873"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 8a 2c 1f 40 30 f5 48 3b bc 24 ?? ?? ?? ?? ?? ?? 4c 89 e9 e8 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 40 88 2c 38 48 ff c7 48 89 bc 24 ?? ?? ?? ?? 40 0f b6 c6 6b f0 9d 40 80 c6 32 48 83 ff 0f}  //weight: 10, accuracy: Low
        $x_1_2 = "ClipboardServer.exe" ascii //weight: 1
        $x_1_3 = "AmsiScanBuffer" ascii //weight: 1
        $x_1_4 = "cmd.exe /e:ON /v:OFF /d /c \"batch file arguments are invalid" ascii //weight: 1
        $x_1_5 = "KillTimer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_ABRS_2147966530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.ABRS!MTB"
        threat_id = "2147966530"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 d2 f7 f6 8d 42 01 8a 04 03 41 30 44 0d ?? 48 ff c1 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_ABRS_2147966530_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.ABRS!MTB"
        threat_id = "2147966530"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 d2 41 f7 f5 8d 42 01 41 0f b6 04 01 30 04 0b 48 83 c1 01 44 39 c1 89 c8 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_ABRS_2147966530_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.ABRS!MTB"
        threat_id = "2147966530"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 39 f9 89 c8 ?? ?? 31 d2 f7 ?? 8d 42 01 8a 04 [0-2] 30 04 0c 48 ff c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_PGRS_2147966699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.PGRS!MTB"
        threat_id = "2147966699"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c8 73 13 31 d2 f7 f6 8d 42 01 8a 04 03 41 30 04 0e 48 ff c1 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_ZOF_2147966780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.ZOF!MTB"
        threat_id = "2147966780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 d2 f7 f7 8d 42 01 41 0f b6 44 05 00 41 30 04 08 48 83 c1 01 44 39 c9 89 c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_VGX_2147967400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.VGX!MTB"
        threat_id = "2147967400"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff 8d f8 01 00 00 31 c0 48 8b 8d f0 01 00 00 8a 14 01 30 94 05 10 02 00 00 48 ff c0 48 83 f8 10 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_VGK_2147967988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.VGK!MTB"
        threat_id = "2147967988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ff 0b 77 29 48 8d 0c 3e e8 [0-4] 0f b6 0c 1f 0f b7 54 1f 01 c1 e2 08 01 d1 81 c1 [0-4] 31 c1 89 4c 3c 40 48 83 c7 04 eb d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_RustyStealer_MK_2147968836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyStealer.MK!MTB"
        threat_id = "2147968836"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "crystalxrat.net" ascii //weight: 15
        $x_10_2 = "killerdefender_excluderdisable_task_manager" ascii //weight: 10
        $x_5_3 = "client/src/stealth/antiforensics.rs" ascii //weight: 5
        $x_3_4 = "client/src/persist/comhijack.rs" ascii //weight: 3
        $x_2_5 = "client/src/steal/mod.rs" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

