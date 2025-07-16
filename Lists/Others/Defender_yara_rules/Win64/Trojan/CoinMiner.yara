rule Trojan_Win64_CoinMiner_C_2147720589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.C"
        threat_id = "2147720589"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 65 65 62 6f 6e 64 39 38 36 40 67 6d 61 69 6c 2e 63 6f 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = "leebond986@gmail.com:x" ascii //weight: 1
        $x_1_3 = "150.8.121.99" ascii //weight: 1
        $x_1_4 = "stratum+tcp://xmr.pool.minergate.com:45560" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_P_2147724379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.P!bit"
        threat_id = "2147724379"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "svchost.exe install Windows" ascii //weight: 1
        $x_1_2 = "-a cryptonight-lite -o stratum+tcp://aeon.pool.minergate.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_CP_2147727333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.CP!bit"
        threat_id = "2147727333"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ParMtx@CPURunOnce#" wide //weight: 1
        $x_1_2 = "\\RigStIn\\nheqminer.exe" wide //weight: 1
        $x_1_3 = "zec.pool.minergate.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_QZ_2147728304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.QZ!bit"
        threat_id = "2147728304"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "shutdown -s -t" ascii //weight: 2
        $x_2_2 = {6f 70 65 6e 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 2, accuracy: High
        $x_2_3 = {b9 4d 5a 00 00 66 39 08 75 33 48 63 48 3c 48 03 c8 81 39 50 45 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {48 63 ca 8d 42 ?? ff c2 30 44 0c 30 83 fa 0c 72 ef}  //weight: 2, accuracy: Low
        $x_1_5 = {48 63 ca 8a c2 41 2a c1 41 03 d7 30 44 0c ?? 83 fa ?? 72 ec}  //weight: 1, accuracy: Low
        $x_1_6 = {48 63 ca 41 8d 04 11 41 03 d7 30 44 0c ?? 83 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CoinMiner_RC_2147728627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.RC!bit"
        threat_id = "2147728627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shutdown -s -t" ascii //weight: 1
        $x_1_2 = "schtasks /create /tn" ascii //weight: 1
        $x_1_3 = "--max-cpu-usage=" ascii //weight: 1
        $x_1_4 = "--cuda-bfactor=12" ascii //weight: 1
        $x_1_5 = "inheritance:e /deny \"SYSTEM:(R,REA,RA,RD)" ascii //weight: 1
        $x_1_6 = "https://2no.co" ascii //weight: 1
        $x_1_7 = "Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe" ascii //weight: 1
        $x_1_8 = "Program Files\\Windows Defender\\ConfigSecurityPolicy.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_2147729902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.MTC!bit"
        threat_id = "2147729902"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTC: an internal category used to refer to some threats"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 48 8d [0-16] 54 24 30 48 03 ?? 8d 48 40 ff ?? 30 0a 83 [0-16] 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 c7 44 ?? ?? 6e 70 7a 73 33 ed c7 44 ?? ?? 71 75 74 6a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_CoinMiner_RJ_2147731067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.RJ"
        threat_id = "2147731067"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 0f b6 ca 4d 8d 5b 04 41 80 c2 04 45 8d 41 01 41 8d 49 fc 48 63 d1 0f b6 0c 02 41 30 4b fc 41 8d 49 fd 48 63 d1 0f b6 0c 02 41 30 0c 00 41 8d 49 fe 48 63 d1 45 8d 41 02 0f b6 0c 02 41 30 0c 00 41 8d 49 ff 48 63 d1 45 8d 41 03 0f b6 0c 02 41 30 0c 00 41 80 fa 10 72 a6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_UK_2147741445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.UK"
        threat_id = "2147741445"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 56 00 43 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 31 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 56 00 43 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "e:\\project dream\\first release source\\xmr-stak-cpu-" wide //weight: 1
        $x_1_5 = "hash self-test failed. This might be caused by bad compiler optimizations." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_GA_2147780853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.GA!MTB"
        threat_id = "2147780853"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "--donate-l" ascii //weight: 10
        $x_10_2 = "Select CommandLine from Win32_Process where Name='{0}'" ascii //weight: 10
        $x_1_3 = "MrpENkGZg4WBldyxqu1jzg==" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "Watchdog" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "\\root\\cimv2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CoinMiner_AMT_2147787527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.AMT!MTB"
        threat_id = "2147787527"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fa 25 33 00 16 00 00 01 00 00 00 01 00 00 00 02 00 00 00 01 00 00 00 01 00 00 00 01 00 00 00 01}  //weight: 10, accuracy: High
        $x_3_2 = "c:\\windo" ascii //weight: 3
        $x_3_3 = "m32\\cm" ascii //weight: 3
        $x_3_4 = "d.exe" ascii //weight: 3
        $x_3_5 = "AcquireSRWLockExclusive" ascii //weight: 3
        $x_3_6 = "nwgold_fast_" ascii //weight: 3
        $x_3_7 = "CreateSymbolicLinkW" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_GB_2147794195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.GB!MTB"
        threat_id = "2147794195"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "--donate-l" ascii //weight: 10
        $x_10_2 = "Select CommandLine from Win32_Process where Name='{0}'" ascii //weight: 10
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "Watchdog" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "\\root\\cimv2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CoinMiner_GC_2147794196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.GC!MTB"
        threat_id = "2147794196"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "payload" ascii //weight: 1
        $x_1_2 = "<wallet>" ascii //weight: 1
        $x_1_3 = "<coin>" ascii //weight: 1
        $x_1_4 = "<stopMining>" ascii //weight: 1
        $x_1_5 = "<KeepAlive>" ascii //weight: 1
        $x_1_6 = "<IsConnected>" ascii //weight: 1
        $x_1_7 = "<injection>" ascii //weight: 1
        $x_1_8 = "<Regex>" ascii //weight: 1
        $x_1_9 = "Clipboard" ascii //weight: 1
        $x_1_10 = "CPUMining" ascii //weight: 1
        $x_1_11 = "Powershell" ascii //weight: 1
        $x_1_12 = "Grabber" ascii //weight: 1
        $x_1_13 = "Phantom_Miner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_Win64_CoinMiner_RDC_2147836833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.RDC!MTB"
        threat_id = "2147836833"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c8 41 39 cb 7e ?? 99 41 f7 f9 48 63 d2 41 8a 04 12 41 30 04 08 48 ff c1}  //weight: 2, accuracy: Low
        $x_1_2 = "requestedExecutionLevel level=\"requireAdministrator\"" ascii //weight: 1
        $x_1_3 = "requestedPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_SPQA_2147837800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.SPQA!MTB"
        threat_id = "2147837800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Windows\\WinS\\xcopy.exe" ascii //weight: 2
        $x_2_2 = "-o xmr.pool.minergate.com:45701 " ascii //weight: 2
        $x_2_3 = "-u 49P7pttLu6jK4gMEGM4ujkD9ugCSUMaidQQMfdWz8kMpbZfzbkLNyoCHkyZd3tjCg8aoZGqQSiJRQhqhcoWzCHEPM4DNUxP --cpu-priority=0 -p x -k" ascii //weight: 2
        $x_1_4 = "%18\\SamuraiVandalism.exe" ascii //weight: 1
        $x_1_5 = "SYSTEM\\ControlSet001\\services\\WMS\\Parameters\\AppExit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_DC_2147841095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.DC!MTB"
        threat_id = "2147841095"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c1 48 89 f2 83 e1 ?? 48 c1 e1 ?? 48 d3 ea 41 30 14 04 48 83 c0 ?? 48 83 f8 ?? 75 ?? 41 c6 44 24 [0-2] 41 83 e5 ?? 43 32 3c 2c 41 88 3c 1e 48 83 c3 ?? 48 39 dd 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_EC_2147841687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.EC!MTB"
        threat_id = "2147841687"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {4c 89 45 d8 41 0f ba e0 09 41 8b c7 45 8b c3 45 8b cc 0f a2 45 0f 43 c7 45 33 d2 89 45 d0 89 5d d4 89 4d d8 33 c9 89 55 dc 41 8b c7 0f a2 41 0f ba e2 09 4c 89 55 d0}  //weight: 4, accuracy: High
        $x_3_2 = {4c 8d 65 d0 4c 8b eb 4d 03 e0 49 f7 dc 49 f7 dd 43 8d 04 16 30 03 85 c9 75 41}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_EC_2147841687_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.EC!MTB"
        threat_id = "2147841687"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a0694063.xsph.ru/GPU6.zip" ascii //weight: 1
        $x_1_2 = "a0694063.xsph.ru/UpSys.exe" ascii //weight: 1
        $x_1_3 = "C:\\ProgramData\\Data\\GPU.zip" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\UpSys.exe" ascii //weight: 1
        $x_1_5 = "Name WinNet -PropertyType String -Value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_EM_2147847659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.EM!MTB"
        threat_id = "2147847659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {4d 8d 40 01 41 8b c1 41 ff c1 f7 f7 0f b6 04 32 41 30 40 ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_EM_2147847659_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.EM!MTB"
        threat_id = "2147847659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mining.subscribe" ascii //weight: 1
        $x_1_2 = "cpuminer/1.0.4" ascii //weight: 1
        $x_1_3 = "X-Mining-Extensions: midstate" ascii //weight: 1
        $x_1_4 = "X-Long-Polling" ascii //weight: 1
        $x_1_5 = "X-Reject-Reason" ascii //weight: 1
        $x_1_6 = "X-Stratum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_EM_2147847659_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.EM!MTB"
        threat_id = "2147847659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellExecuteExW" ascii //weight: 1
        $x_1_2 = "GetTempFileNameW" ascii //weight: 1
        $x_1_3 = "LoadLibraryExW" ascii //weight: 1
        $x_1_4 = "@echo off" ascii //weight: 1
        $x_1_5 = "start abc.vbs" ascii //weight: 1
        $x_1_6 = "start ethereum-classic-f2pool.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_AB_2147849949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.AB!MTB"
        threat_id = "2147849949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 c0 48 89 c1 48 89 d7 83 e1 07 48 c1 e1 03 48 d3 ef 66 41 31 3c 44 48 83 c0 01 48 83 f8 1b 75 e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_EN_2147851463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.EN!MTB"
        threat_id = "2147851463"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 d2 49 63 ca 49 3b c9 48 0f 45 d6 42 8a 04 02 48 8d 72 01 30 03 33 c0 49 3b c9 41 0f 45 c2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_PABA_2147890330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.PABA!MTB"
        threat_id = "2147890330"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 4a 14 0f b7 02 66 2d 1b 4a 66 25 ff 00 66 89 02 48 83 c2 02 48 39 ca 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {66 2d 71 0a 66 25 ff 00 66 89 02 48 83 c2 02 48 39 ca 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_NC_2147901317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.NC!MTB"
        threat_id = "2147901317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 0c 83 fa ?? 75 2a e8 2a 08 00 00 eb 23 48 8d 1d ?? ?? ?? ?? 48 8d 35 45 92 53 00 48 39 f3}  //weight: 5, accuracy: Low
        $x_1_2 = "opeohcz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_NC_2147901317_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.NC!MTB"
        threat_id = "2147901317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 31 c0 8b 05 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 49 89 ca 8f}  //weight: 2, accuracy: Low
        $x_2_2 = {58 48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 8b 0d ?? ?? ?? ?? e8 a8 65 00 00 89 05}  //weight: 2, accuracy: Low
        $x_1_3 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_XZ_2147903210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.XZ!MTB"
        threat_id = "2147903210"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 c2 40 02 c5 40 02 c7 45 3b c4 0f b6 e8 44 0f 4d c3 49 ff c1 41 8b 44 ab 08 43 89 44 8b 04 41 89 7c ab 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_SIM_2147907278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.SIM!MTB"
        threat_id = "2147907278"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ef 03 d7 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 3a 40 0f b6 c7 2a c1 04 32 41 30 00 ff c7 4d 8d 40 01 83 ff 27 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_RM_2147908489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.RM!MTB"
        threat_id = "2147908489"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 02 34 3c 88 02 48 ff c2 8a 02 34 e8 88 02 48 ff c2 48 ff ce 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_NA_2147909349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.NA!MTB"
        threat_id = "2147909349"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MicroBitcoin" ascii //weight: 5
        $x_5_2 = "getmininginfo" ascii //weight: 5
        $x_2_3 = "yescryptr32" ascii //weight: 2
        $x_2_4 = "BitZeny" ascii //weight: 2
        $x_1_5 = "Miner thread priority" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_ASJ_2147928149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.ASJ!MTB"
        threat_id = "2147928149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 01 d0 0f b6 00 89 c1 8b 85 ?? ?? 00 00 48 8b 95 ?? ?? 00 00 48 01 c2 89 c8 32 85 ?? ?? 00 00 88 02 83 85 ?? ?? 00 00 01 8b 85 ?? ?? 00 00 39 85 ?? ?? 00 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_PBH_2147928683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.PBH!MTB"
        threat_id = "2147928683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://file.hitler.fans/xmrig.exe" ascii //weight: 2
        $x_2_2 = "hitlerMinerTool" ascii //weight: 2
        $x_2_3 = "Release\\XmrigMonitor.pdb" ascii //weight: 2
        $x_1_4 = "taskkill /f /t /im " ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_BQ_2147930885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.BQ!MTB"
        threat_id = "2147930885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c82a3b21-5c19-4d42-af17-8f00fb3599c7" ascii //weight: 2
        $x_1_2 = "Cf23T3Ds6kQAN4Ou" ascii //weight: 1
        $x_1_3 = "Hc3yeA5nmnqKjbL1" ascii //weight: 1
        $x_1_4 = "F.DNH(J" ascii //weight: 1
        $x_1_5 = "N@P RHPm" ascii //weight: 1
        $x_1_6 = ":/data/app.exe" ascii //weight: 1
        $x_1_7 = {08 60 00 8a 02 a2 04 76 02 00 00 01 04 01 00 04 42 00 00 19 14 06 00 14 64 09 00 14 34 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_BR_2147933743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.BR!MTB"
        threat_id = "2147933743"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 58 6f e4 74 7c a4 ff 34 4a 95 ff 23 37 7c ff 21 34 73 ff 1e 32 6d ff 19 2b 5f ff 23 38 75 ff 24 3d 81 ff 42 5b 99 ff 40 58}  //weight: 2, accuracy: High
        $x_2_2 = {3c 01 03 1a ab 17 1d 4a fc 3c 46 7b ff 31 48 91 ff 31 4a 96 ff 33 53 9a ff 34 47 83 ff 08 0c 34 dc}  //weight: 2, accuracy: High
        $x_1_3 = {75 52 30 33 45 74 00 00 66 66 64 73}  //weight: 1, accuracy: High
        $x_1_4 = "4dab2a97-02b0-4451-a295-ae8df7084d62" ascii //weight: 1
        $x_1_5 = "Click and drag this color onto the robot!" ascii //weight: 1
        $x_1_6 = "robot_demo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_B_2147936260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.B!MTB"
        threat_id = "2147936260"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 1e 61 9a a1 9c 48 8b 7c 24 08 40 c0 e7 94 48 f7 df 48 8b bc 3c 10 61 9a a1 48 c7 44 24 10 4b 71 f5 0b ff 74 24 00 9d 48 8d ?? ?? ?? e8 ?? ?? ?? ?? 48 c7 44 24 00 2f 7a ce 79 e8 ?? ?? ?? ?? aa bb d0 00 4a ea f8 c8 32 03 78}  //weight: 2, accuracy: Low
        $x_2_2 = {c1 e8 0b 80 fb 9f f9 0f af c1 f9 45 84 f0 3b f8 0f 83 2b 00 00 00 44 8b c0 66 35 1d a0 66 40 0f b6 c4 b8 00 08 00 00 2b c1 f9 c1 f8 05 66 03 c1 03 d2 66 42 89 04 5e e9 00 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_C_2147936274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.C!MTB"
        threat_id = "2147936274"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c1 5f a9 ?? ?? ?? ?? 30 8c 83 ?? ?? ?? ?? 21 ed d6 c0 d3 ?? ed d5 79 52 6d 8b 30 80 e2 ?? 9c e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_BT_2147936687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.BT!MTB"
        threat_id = "2147936687"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 44 24 30 0f be 00 89 44 24 04 48 8b 44 24 30 48 ff c0 48 89 44 24 30 48 8b 44 24 28 0f be 00 33 44 24 04 48 8b 4c 24 28 88 01 48 8b 44 24 28 48 ff c0 48 89 44 24 28 eb}  //weight: 3, accuracy: High
        $x_2_2 = {81 e1 ff 00 00 00 48 63 c9 48 8d 15 ?? ?? ?? 00 33 04 8a b9 04 00 00 00 48 6b c9 03 48 8b 54 24 08 33 04 0a 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_PPCD_2147939601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.PPCD!MTB"
        threat_id = "2147939601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 89 44 24 60 48 8b 44 24 60 8b 40 10 48 8b 4c 24 60 8b 49 14 48 8b 94 24 30 01 00 00 48 03 d1 48 8b ca 48 8b 54 24 60 8b 52 0c 4c 8b 44 24 68 4c 03 c2 49 8b d0 48 c7 44 24 20 00 00 00 00 44 8b c8 4c 8b c1 48 8b 4c 24 78 ff 15}  //weight: 4, accuracy: High
        $x_2_2 = {41 b9 20 00 00 00 44 8b c0 48 8b d1 48 8b 4c 24 78 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_ASTA_2147941257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.ASTA!MTB"
        threat_id = "2147941257"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4d 8b c5 48 83 3d ?? ?? ?? ?? 0f 4c 0f 47 05 ?? ?? ?? ?? 33 d2 48 8b c1 48 f7 35 ?? ?? ?? ?? 49 03 d0 4c 8d 44 24 50 48 83 7c 24 68 0f 4c 0f 47 44 24 50 0f b6 02 41 32 04 09 41 88 04 08 48 ff c1 49 3b ca 72}  //weight: 5, accuracy: Low
        $x_1_2 = "\\Sapphire_Miner_Source\\SapphireClient\\x64\\Release\\SapphireClient.pdb" ascii //weight: 1
        $x_1_3 = "powershell -Command \"Add-MpPreference -ExclusionProcess 'cmd.exe'; Add-MpPreference -ExclusionPath 'C:\\'\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_CoinMiner_KK_2147943866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.KK!MTB"
        threat_id = "2147943866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {76 00 70 00 70 00 65 00 70 00 7a 00 7d 00 7f 00 60 00 0f 00 7e 00 62 00 61 00 60 00 67 00 60 00 13 00 14 00 12 00 1b 00 6e 00 27 00 5b 00 00 00 67 42 5b 7d 57 4e 5e 4e 7e 4c 56 34 28 21 22 28}  //weight: 6, accuracy: High
        $x_2_2 = {8b c2 c1 e8 1f 03 d0 0f b7 c2 6b d0 ?? 41 0f b7 c2 41 ff c2 66 2b c2 66 83 c0 ?? 66 31 41 fe 41 83 fa 1d}  //weight: 2, accuracy: Low
        $x_3_3 = {4c 8d 85 a8 04 00 00 49 83 fb 0f 4d 0f 47 c2 49 8b cd 48 83 3d ?? 0e 05 00 0f 48 0f 47 0d ?? ?? 05 00 33 d2 49 8b c1 48 f7 35 ?? ?? 05 00 48 03 d1 48 8d 8d 38 05 00 00 48 83 bd 50 05 00 00 0f 48 0f 47 8d 38 05 00 00 43 0f b6 04 08 32 02 42 88 04 09 49 ff c1 4c 3b cb}  //weight: 3, accuracy: Low
        $x_1_4 = "xai830k.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_CoinMiner_SX_2147946571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CoinMiner.SX!MTB"
        threat_id = "2147946571"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 c7 44 24 38 08 00 00 00 48 8b 44 24 38 48 89 44 24 48 48 c7 44 24 40 00 00 00 00 48 8d 44 24 40 48 89 44 24 20 4c 8b 4c 24 48 4c 8d 44 24 78 48 8b 54 24 50 48 8b 84 24 80 00 00 00 48 8b 08 ff 15 ?? ?? ?? ?? 85 c0 75 17}  //weight: 20, accuracy: Low
        $x_20_2 = {48 c7 c0 ff ff ff ff e9 ?? ?? ?? ?? c7 44 24 78 00 00 00 00 48 c7 44 24 20 00 00 00 00 4c 8d 4c 24 78 44 8b 84 24 b0 00 00 00 48 8b 94 24 a8 00 00 00 48 8b 4c 24 60 ff 15 ?? ?? ?? ?? 85 c0 75 46}  //weight: 20, accuracy: Low
        $x_10_3 = "WkDDHiThxzav" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

