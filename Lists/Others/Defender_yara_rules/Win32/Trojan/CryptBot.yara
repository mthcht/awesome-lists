rule Trojan_Win32_CryptBot_ET_2147761969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.ET!MTB"
        threat_id = "2147761969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mutexname-svcmutex" ascii //weight: 1
        $x_1_2 = "COMSPEC %s /c del %s" ascii //weight: 1
        $x_1_3 = "%SystemRoot%\\System32\\svchost.exe -k netsvcs" ascii //weight: 1
        $x_1_4 = "\\update.ini" ascii //weight: 1
        $x_1_5 = "ServiceDllUnloadOnStop" ascii //weight: 1
        $x_1_6 = "install On Has proxy!" ascii //weight: 1
        $x_1_7 = "file.data" ascii //weight: 1
        $x_1_8 = "InstallSrv %s  %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_CryptBot_QLM_2147809826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.QLM!MTB"
        threat_id = "2147809826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d 08 2b 0d ?? ?? ?? ?? 33 4d 0c 83 c1 64 2b c9 33 4d 0c 2b 0d ?? ?? ?? ?? 89 4d 08 be 10 00 00 00 33 75 08 81 c6 ?? ?? ?? ?? 33 75 0c 89 75 ec}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 08 33 05 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 89 45 fc 8b 45 08 81 c0 ?? ?? ?? ?? 83 f0 ?? 81 e8 ?? ?? ?? ?? 33 45 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_GTS_2147810542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.GTS!MTB"
        threat_id = "2147810542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 08 8b 4d 10 03 0d ?? ?? ?? ?? 33 4d 20 83 e9 24 03 c9 2b 4d 08 89 0d ?? ?? ?? ?? 68 45 a0 74 00 ff 15 ?? ?? ?? ?? 89 45 fc 83 f8 00 0f 85 c0 c5 ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {8b ce 81 f1 ?? ?? ?? ?? 83 e9 1d 03 0d ?? ?? ?? ?? 33 ce 03 0d 91 a2 74 00 89 4d e4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_CC_2147811442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.CC!MTB"
        threat_id = "2147811442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 8b c6 f7 75 08 8a 0c 1a 30 0c 3e 46 81 fe ?? ?? ?? ?? 72}  //weight: 5, accuracy: Low
        $x_5_2 = {0f af d1 8b 4d 08 8b c1 56 8b 35 ?? ?? ?? ?? c1 e8 ?? 88 44 96 01 8b c1 88 0c 96 c1 e8 ?? c1 e9 ?? 88 44 96 03 88 4c 96 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_NEAA_2147837435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.NEAA!MTB"
        threat_id = "2147837435"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 8b c6 f7 75 08 8a 0c 1a 30 0c 3e 46 81 fe ?? ?? 00 00 72 ea}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_BS_2147837922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.BS!MTB"
        threat_id = "2147837922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {47 23 fe 8d 44 3d 88 0f b6 08 03 4d 84 23 ce 89 4d 84 8d 4c 0d 88 8a 11 30 10 8a 10 30 11 8a 11 30 10 0f b6 00 0f b6 09 8b 55 80 03 c1 23 c6 8a 44 05 88 03 d3 30 02 43 3b 9d 98 00 00 00 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_CD_2147838501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.CD!MTB"
        threat_id = "2147838501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 0f af 45 0c 8b 0d ?? ?? ?? ?? 8d 14 81 89 55 fc b8 ?? ?? ?? ?? 6b c8 ?? ba ?? ?? ?? ?? 6b c2 ?? 8b 55 fc 8a 4c 0d 10 88 0c 02 ba ?? ?? ?? ?? c1 e2 ?? b8 ?? ?? ?? ?? c1 e0 ?? 8b 4d fc 8a 54 15 10 88 14 01 b8 ?? ?? ?? ?? 6b c8 ?? ba ?? ?? ?? ?? 6b c2 ?? 8b 55 fc 8a 4c 0d 10 88 0c 02 ba ?? ?? ?? ?? d1 e2 b8 ?? ?? ?? ?? d1 e0 8b 4d fc 8a 54 15 10 88 14 01}  //weight: 5, accuracy: Low
        $x_3_2 = "ResumeThread" ascii //weight: 3
        $x_2_3 = "GetThreadTimes" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_CE_2147839269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.CE!MTB"
        threat_id = "2147839269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 fc 8a 44 05 10 88 04 0a b9 ?? ?? ?? ?? 6b d1 ?? b8 ?? ?? ?? ?? 6b c8 ?? 8b 45 fc 8a 54 15 10 88 14 08 b8 ?? ?? ?? ?? d1 ?? b9 ?? ?? ?? ?? d1 ?? 8b 55 fc 8a 44 05 10 88 04 0a b9 ?? ?? ?? ?? 6b d1 03 b8 ?? ?? ?? ?? 6b c8 03 8b 45 fc 8a 54 15 10 88 14 08}  //weight: 5, accuracy: Low
        $x_3_2 = "ResumeThread" ascii //weight: 3
        $x_2_3 = "GetThreadTimes" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_LK_2147839389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.LK!MTB"
        threat_id = "2147839389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e8 08 88 44 96 01 8b c1 88 0c 96 c1 e8 18 c1 e9 10 88 44 96 03 88 4c 96 02}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d 08 8d 14 90 8b c1 88 0a c1 e8 08 88 42 01 8b c1 c1 e8 18 c1 e9 10 88 42 03 88 4a 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptBot_CX_2147840463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.CX!MTB"
        threat_id = "2147840463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c8 40 3d ?? ?? ?? ?? 7c ?? 8b 45 08 32 ca 80 f1 ?? 88 0c 06 b9 ?? ?? ?? ?? 46 3b f7 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_MA_2147843133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.MA!MTB"
        threat_id = "2147843133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 0c 8d 4e 01 8a 04 06 88 04 1a 8b c2 33 d2 8b 75 18 f7 75 14 ff 45 fc 03 f1 85 d2 8b 55 fc 0f 45 f1 3b 55 10 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_RG_2147845377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.RG!MTB"
        threat_id = "2147845377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec a1 ?? ?? ?? ?? 0f af ca 8b 55 08 89 14 88 5d c3 [0-21] 55 8b ec a1 ?? ?? ?? ?? 8b 55 08 89 14 88 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_CCHB_2147901249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.CCHB!MTB"
        threat_id = "2147901249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Google\\Chrome\\User Data" wide //weight: 1
        $x_1_2 = "Brave-Browser\\User Data" wide //weight: 1
        $x_1_3 = "& timeout 4 & del /f /q" wide //weight: 1
        $x_1_4 = "\\_Files\\_Information.txt" wide //weight: 1
        $x_1_5 = "\\files_\\system_info.txt" wide //weight: 1
        $x_1_6 = "\\files_\\screenshot" wide //weight: 1
        $x_1_7 = "wallet.dat" wide //weight: 1
        $x_1_8 = "\\_Files\\_Wallet" wide //weight: 1
        $x_1_9 = "\\_Files\\_Chrome" wide //weight: 1
        $x_1_10 = "\\_Files\\_Opera" wide //weight: 1
        $x_1_11 = "\\_Files\\_Brave" wide //weight: 1
        $x_1_12 = "\\_Files\\_Firefox" wide //weight: 1
        $x_1_13 = "\\_Files\\Binance" wide //weight: 1
        $x_1_14 = "\\files_\\cryptocurrency" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_CCJD_2147916056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.CCJD!MTB"
        threat_id = "2147916056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "addCryptoWallets" ascii //weight: 5
        $x_1_2 = "UserName (ComputerName):" wide //weight: 1
        $x_1_3 = "OS:" wide //weight: 1
        $x_1_4 = "Keyboard Languages:" wide //weight: 1
        $x_1_5 = "CPU:" wide //weight: 1
        $x_1_6 = "GPU:" wide //weight: 1
        $x_1_7 = "VirtualBox" wide //weight: 1
        $x_1_8 = "Process Hacker 2" wide //weight: 1
        $x_1_9 = "Sandbox" wide //weight: 1
        $x_1_10 = "Opera Crypto" wide //weight: 1
        $x_1_11 = "\\User Data" wide //weight: 1
        $x_1_12 = "BraveSoftware" wide //weight: 1
        $x_1_13 = "\\Ledger Live" wide //weight: 1
        $x_1_14 = "Exodus Wallet" wide //weight: 1
        $x_1_15 = "\\ElectronCash\\wallets" wide //weight: 1
        $x_1_16 = "wallet.dat" wide //weight: 1
        $x_1_17 = "Bitcoin" wide //weight: 1
        $x_1_18 = "Ethereum" wide //weight: 1
        $x_1_19 = "Browsers" wide //weight: 1
        $x_1_20 = "/c powershell -NoP -NonI -ExecutionPolicy Bypass -Command \"$Resp = Invoke-WebRequest -Uri" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptBot_CCJE_2147921781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.CCJE!MTB"
        threat_id = "2147921781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "UserName (ComputerName):" wide //weight: 5
        $x_5_2 = "OS:" wide //weight: 5
        $x_5_3 = "Keyboard Languages:" wide //weight: 5
        $x_5_4 = "CPU:" wide //weight: 5
        $x_5_5 = "GPU:" wide //weight: 5
        $x_5_6 = "VirtualBox" wide //weight: 5
        $x_1_7 = "Opera Software\\Opera Developer" wide //weight: 1
        $x_1_8 = "atomic\\Local Storage\\leveldb" wide //weight: 1
        $x_1_9 = "\\User Data" wide //weight: 1
        $x_1_10 = "McAfee_Inc" wide //weight: 1
        $x_1_11 = "binance" wide //weight: 1
        $x_1_12 = "Electrum" wide //weight: 1
        $x_1_13 = "wallet.dat" wide //weight: 1
        $x_1_14 = "\\exodus.wallet" wide //weight: 1
        $x_1_15 = "Oxygen - Atomic Crypto Wallet" wide //weight: 1
        $x_1_16 = "Enkrypt - Multichain Crypto Wallet" wide //weight: 1
        $x_1_17 = "Rabby Wallet" wide //weight: 1
        $x_1_18 = "Xverse Wallet" wide //weight: 1
        $x_1_19 = "UniSat Wallet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_5_*) and 10 of ($x_1_*))) or
            ((6 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptBot_GPA_2147922168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.GPA!MTB"
        threat_id = "2147922168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "//update-ledger.net/update" ascii //weight: 4
        $x_1_2 = "UseBasicParsing -UserAgent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_HZ_2147926699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.HZ!MTB"
        threat_id = "2147926699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 80 66 00 00 10 00 00 00 6c 27 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 90 66 00 00 00 00 00 00 7c 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_2_2 = {20 20 20 00 20 20 20 20 00 70 66 00 00 10 00 00 00 68 27 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 80 66 00 00 00 00 00 00 78 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptBot_EZ_2147926884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.EZ!MTB"
        threat_id = "2147926884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 d4 05 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_EZ_2147926884_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.EZ!MTB"
        threat_id = "2147926884"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 e0 70 00 00 10 00 00 00 78 27 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 f0 70 00 00 00 00 00 00 88 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_RZ_2147926885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.RZ!MTB"
        threat_id = "2147926885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 b0 6d 00 00 10 00 00 00 8a 28 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 c0 6d 00 00 02 00 00 00 9a 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_RZ_2147926885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.RZ!MTB"
        threat_id = "2147926885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 c0 06 00 00 10 00 00 00 d8 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 e0 01 00 00 00 d0 06 00 00 02 00 00 00 e8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_2_2 = {20 20 20 00 20 20 20 20 00 c0 06 00 00 10 00 00 00 d8 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 e0 01 00 00 00 d0 06 00 00 02 00 00 00 e8 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptBot_DZ_2147926970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.DZ!MTB"
        threat_id = "2147926970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 50 65 00 00 10 00 00 00 6c 27 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 60 65 00 00 00 00 00 00 7c 27 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_LZ_2147927501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.LZ!MTB"
        threat_id = "2147927501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 00 00 12 00 00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 9c 05 00 00 00 60 00 00 00 06 00 00 00 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_LZ_2147927501_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.LZ!MTB"
        threat_id = "2147927501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 30 26 00 00 10 00 00 00 aa 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 40 26 00 00 02 00 00 00 ba 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_2_2 = {20 20 20 00 20 20 20 20 00 30 05 00 00 10 00 00 00 46 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 40 05 00 00 02 00 00 00 56 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptBot_ZZ_2147927601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.ZZ!MTB"
        threat_id = "2147927601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 90 24 00 00 10 00 00 00 62 01 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 f0 01 00 00 00 a0 24 00 00 02 00 00 00 72 01 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_2_2 = {20 20 20 00 20 20 20 20 00 d0 04 00 00 10 00 00 00 1e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 e0 04 00 00 02 00 00 00 2e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_2_3 = {20 20 20 00 20 20 20 20 00 50 05 00 00 10 00 00 00 5e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 60 05 00 00 02 00 00 00 6e 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptBot_ZC_2147927694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.ZC!MTB"
        threat_id = "2147927694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 c0 77 00 00 10 00 00 00 40 28 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 d0 77 00 00 02 00 00 00 50 28 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
        $x_2_2 = {20 20 20 00 20 20 20 20 00 10 05 00 00 10 00 00 00 32 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 20 05 00 00 02 00 00 00 42 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CryptBot_XZ_2147928863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.XZ!MTB"
        threat_id = "2147928863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 b0 07 00 00 10 00 00 00 3c 04 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 6c 16 00 00 00 c0 07 00 00 08 00 00 00 4c 04 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_NZ_2147929259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.NZ!MTB"
        threat_id = "2147929259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 20 20 20 20 00 20 05 00 00 10 00 00 00 64 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 30 05 00 00 02 00 00 00 74 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_ZA_2147933339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.ZA!MTB"
        threat_id = "2147933339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 72 73 72 63 00 00 00 9c 05 00 00 00 60 00 00 00 06 00 00 00 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_BM_2147933473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.BM!MTB"
        threat_id = "2147933473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 51 08 32 51 19 88 50 08 c6 05}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4c 24 08 8b 44 24 04 0f b6 11 32 51 ?? 88 10 0f b6 51 01 32 51}  //weight: 2, accuracy: Low
        $x_1_3 = "t.me/m08mbk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CryptBot_DA_2147938204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.DA!MTB"
        threat_id = "2147938204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "612"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "Browsers\\Cookies\\Google" ascii //weight: 100
        $x_1_2 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_4 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_6 = "Browsers\\Cookies\\Opera" ascii //weight: 100
        $x_1_7 = {4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 [0-15] 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_8 = {4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c [0-15] 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_9 = {4f 00 70 00 65 00 72 00 61 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 [0-15] 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_10 = {4f 70 65 72 61 20 53 6f 66 74 77 61 72 65 5c [0-15] 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_11 = "Browsers\\Cookies\\360" ascii //weight: 100
        $x_1_12 = {33 00 36 00 30 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_13 = {33 36 30 43 68 72 6f 6d 65 5c 43 68 72 6f 6d 65 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_14 = {33 00 36 00 30 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_15 = {33 36 30 43 68 72 6f 6d 65 5c 43 68 72 6f 6d 65 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_16 = "Browsers\\Cookies\\CocCoc" ascii //weight: 100
        $x_1_17 = {43 00 6f 00 63 00 43 00 6f 00 63 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_18 = {43 6f 63 43 6f 63 5c 42 72 6f 77 73 65 72 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_19 = {43 00 6f 00 63 00 43 00 6f 00 63 00 5c 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_20 = {43 6f 63 43 6f 63 5c 42 72 6f 77 73 65 72 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_21 = "Browsers\\Cookies\\Comodo" ascii //weight: 100
        $x_1_22 = {43 00 6f 00 6d 00 6f 00 64 00 6f 00 5c 00 44 00 72 00 61 00 67 00 6f 00 6e 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_23 = {43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_24 = {43 00 6f 00 6d 00 6f 00 64 00 6f 00 5c 00 44 00 72 00 61 00 67 00 6f 00 6e 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_25 = {43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_26 = "Browsers\\Cookies\\Slimjet" ascii //weight: 100
        $x_1_27 = {53 00 6c 00 69 00 6d 00 6a 00 65 00 74 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_28 = {53 6c 69 6d 6a 65 74 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_29 = {53 00 6c 00 69 00 6d 00 6a 00 65 00 74 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_30 = {53 6c 69 6d 6a 65 74 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_31 = "Browsers\\Cookies\\Cent" ascii //weight: 100
        $x_1_32 = {43 00 65 00 6e 00 74 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_33 = {43 65 6e 74 42 72 6f 77 73 65 72 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_34 = {43 00 65 00 6e 00 74 00 42 00 72 00 6f 00 77 00 73 00 65 00 72 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_35 = {43 65 6e 74 42 72 6f 77 73 65 72 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_36 = "Browsers\\Cookies\\Torch" ascii //weight: 100
        $x_1_37 = {54 00 6f 00 72 00 63 00 68 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_38 = {54 6f 72 63 68 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_39 = {54 00 6f 00 72 00 63 00 68 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_40 = {54 6f 72 63 68 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_41 = "Browsers\\Cookies\\Vivaldi" ascii //weight: 100
        $x_1_42 = {56 00 69 00 76 00 61 00 6c 00 64 00 69 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_43 = {56 69 76 61 6c 64 69 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_44 = {56 00 69 00 76 00 61 00 6c 00 64 00 69 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_45 = {56 69 76 61 6c 64 69 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
        $x_100_46 = "Browsers\\Cookies\\Brave" ascii //weight: 100
        $x_1_47 = "brave\\LoginData" ascii //weight: 1
        $x_1_48 = "brave\\Cookies" ascii //weight: 1
        $x_100_49 = "Browsers\\Cookies\\Chromium" ascii //weight: 100
        $x_1_50 = {43 00 68 00 72 00 6f 00 6d 00 69 00 75 00 6d 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 44 00 61 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_51 = {43 68 72 6f 6d 69 75 6d 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 44 61 74 61}  //weight: 1, accuracy: Low
        $x_1_52 = {43 00 68 00 72 00 6f 00 6d 00 69 00 75 00 6d 00 5c 00 [0-15] 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_53 = {43 68 72 6f 6d 69 75 6d 5c [0-15] 5c 44 65 66 61 75 6c 74 5c 43 6f 6f 6b 69 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_100_*) and 12 of ($x_1_*))) or
            ((7 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_CryptBot_DB_2147938205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CryptBot.DB!MTB"
        threat_id = "2147938205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "403"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "wallet.dat" ascii //weight: 100
        $x_100_2 = "logins.json" ascii //weight: 100
        $x_100_3 = "cookies.sqlite" ascii //weight: 100
        $x_100_4 = "Passwords.txt" ascii //weight: 100
        $x_100_5 = "Screen.jpg" ascii //weight: 100
        $x_1_6 = "Vivaldi" ascii //weight: 1
        $x_1_7 = "Torch" ascii //weight: 1
        $x_1_8 = "brave" ascii //weight: 1
        $x_1_9 = "Slimjet" ascii //weight: 1
        $x_1_10 = "CentBrowser" ascii //weight: 1
        $x_1_11 = "Comodo" ascii //weight: 1
        $x_1_12 = "CocCoc" ascii //weight: 1
        $x_1_13 = "Google" ascii //weight: 1
        $x_1_14 = "360Chrome" ascii //weight: 1
        $x_1_15 = "Opera" ascii //weight: 1
        $x_1_16 = "Chromium" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 3 of ($x_1_*))) or
            ((5 of ($x_100_*))) or
            (all of ($x*))
        )
}

