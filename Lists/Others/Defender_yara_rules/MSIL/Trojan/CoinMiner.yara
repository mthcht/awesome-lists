rule Trojan_MSIL_CoinMiner_AR_2147697760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AR"
        threat_id = "2147697760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Melt();" wide //weight: 1
        $x_1_2 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 2d 00 6f 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 69 00 6e 00 74 00 2e 00 62 00 69 00 74 00 6d 00 69 00 6e 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 3a 00 38 00 33 00 33 00 32 00 20 00 2d 00 75 00 20 00 [0-32] 20 00 2d 00 70 00 20 00 78 00 20 00 2d 00 74 00 20 00 34 00 20 00 2d 00 67 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_AU_2147711643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AU!bit"
        threat_id = "2147711643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 75 63 6b 00 4f 70 65 6e 4d 6e 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 6f 6c 64 65 72 4d 6e 72 00 70 61 74 68 54 61 72 47 7a 00}  //weight: 1, accuracy: High
        $x_1_3 = {57 72 69 74 65 50 49 44 00 52 65 61 64 50 49 44 00 43 72 65 61 74 65 46 6f 6c 64 65 72 4d 6e 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 61 74 68 4d 6e 72 00 70 61 74 68 53 76 63 68 6f 73 74 00 66 6f 6c 64 65 72 4d 6e 72 00 70 61 74 68 54 61 72 47 7a 00 66 6f 6c 64 65 72 53 76 63 68 6f 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_AX_2147721056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AX!bit"
        threat_id = "2147721056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xSilentMode" ascii //weight: 1
        $x_1_2 = "xBase64Decode" ascii //weight: 1
        $x_1_3 = "xBase64Encode" ascii //weight: 1
        $x_1_4 = "xSendRequest" ascii //weight: 1
        $x_1_5 = "xProcessStart" ascii //weight: 1
        $x_1_6 = "xSetAutoRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_BR_2147722533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.BR!bit"
        threat_id = "2147722533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "apshost.Properties.Resources" wide //weight: 1
        $x_1_2 = "{11111-22222-20001-00001}" wide //weight: 1
        $x_1_3 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 32 38 63 2d 31 00 24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 32 38 64 2d 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_BZ_2147723246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.BZ!bit"
        threat_id = "2147723246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "master/vendor/global/AdobeUpdateManager.exe" wide //weight: 1
        $x_1_2 = "master/vendor/global/AdobeUpdateWorker.exe" wide //weight: 1
        $x_1_3 = "https://github.com/Programmist6996" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_BS_2147723276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.BS!bit"
        threat_id = "2147723276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitcoinMiner" wide //weight: 1
        $x_1_2 = "coin-miner" wide //weight: 1
        $x_1_3 = "cgminer" wide //weight: 1
        $x_1_4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "StartBotKiller" ascii //weight: 1
        $x_1_6 = "SELECT * FROM Win32_VideoController" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_CA_2147723340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.CA!bit"
        threat_id = "2147723340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DetectorIsStart" ascii //weight: 1
        $x_1_2 = "EnemyKiller" ascii //weight: 1
        $x_1_3 = "MinerWritter" ascii //weight: 1
        $x_1_4 = "GoFuckUac" ascii //weight: 1
        $x_1_5 = "Software\\Classes\\mscfile\\shell\\open\\command" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_10_7 = "-o stratum+tcp://" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_CB_2147724353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.CB!bit"
        threat_id = "2147724353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "zec-eu1.nanopool.org:6633" ascii //weight: 5
        $x_2_2 = "powershell -ExecutionPolicy Bypass -windowstyle hidden -noexit" ascii //weight: 2
        $x_2_3 = "netsh advfirewall firewall add rule name" ascii //weight: 2
        $x_1_4 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_5 = "FirewallDisableNotify" ascii //weight: 1
        $x_1_6 = "AntiVirusDisableNotify" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_L_2147724749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.L!bit"
        threat_id = "2147724749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58}  //weight: 1, accuracy: High
        $x_1_2 = {02 03 61 0c 08 1f 11 5a 1f 1b 5b 0c 07 1d 08 58}  //weight: 1, accuracy: High
        $x_1_3 = "Microsoft\\Network\\Connections\\hostdl.exe" ascii //weight: 1
        $x_1_4 = {6d 69 6e 69 6e 67 44 65 76 69 63 65 00 63 70 75 6c 6f 61 64}  //weight: 1, accuracy: High
        $x_1_5 = "minerTask" ascii //weight: 1
        $x_1_6 = "loadingcpu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_OS_2147724785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.OS!bit"
        threat_id = "2147724785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MingC.vbs" wide //weight: 1
        $x_1_2 = "$c71a13fb-8f66-4600-9ac5-09c122912c7a" wide //weight: 1
        $x_2_3 = "4GP.ME/bbtc/" wide //weight: 2
        $x_1_4 = "= CreateObject(\"WinHttp.WinHttpRequest.5.1\")" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_PJ_2147725235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PJ!bit"
        threat_id = "2147725235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 0f 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 1d 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 07 52 00 75 00 6e 00}  //weight: 2, accuracy: High
        $x_1_2 = "pastebin.com/raw/" wide //weight: 1
        $x_1_3 = ".mixtape.moe/" wide //weight: 1
        $x_1_4 = ".pomf.cat/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_CQ_2147725236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.CQ!bit"
        threat_id = "2147725236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 75 70 72 65 6d 65 2e 65 78 65 00 53 75 70 72 65 6d 65 00 6d 73 63 6f 72 6c 69 62 00}  //weight: 1, accuracy: High
        $x_1_2 = {44 65 62 75 67 67 65 72 00 67 65 74 5f 49 73 41 74 74 61 63 68 65 64 00 49 73 4c 6f 67 67 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PN_2147725417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PN!bit"
        threat_id = "2147725417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Y21kIC9jIHBvd2Vyc2hlbGwgLW5vcCAtYyAiImlleChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5n" wide //weight: 2
        $x_1_2 = {35 74 00 65 00 73 00 74 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 1, accuracy: High
        $x_1_3 = "/Create /SC MINUTE /TN " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_PS_2147725593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PS!bit"
        threat_id = "2147725593"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 00 73 65 74 5f 46 69 6c 65 4e 61 6d 65 00 73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77}  //weight: 1, accuracy: High
        $x_1_2 = {47 65 74 50 72 6f 63 65 73 73 65 73 42 79 4e 61 6d 65 00 4b 69 6c 6c}  //weight: 1, accuracy: High
        $x_2_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 2
        $x_2_4 = "stratum+tcp://" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_PT_2147725595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PT!bit"
        threat_id = "2147725595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "stratum+tcp://xmr." wide //weight: 1
        $x_1_2 = {54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 [0-2] 46 00 69 00 6c 00 74 00 65 00 72 00 48 00 6f 00 73 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_IL_2147726250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.IL!bit"
        threat_id = "2147726250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " -o stratum+tcp://xmr." wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_QG_2147727816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.QG!bit"
        threat_id = "2147727816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "obj\\Debug\\WinCalendar.pdb" ascii //weight: 1
        $x_1_2 = "sgvhosts -c sgminerzcash.conf --gpu-reorder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_QH_2147728163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.QH!bit"
        threat_id = "2147728163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2d 00 6f 00 20 00 78 00 6d 00 72 00 2d 00 [0-16] 2e 00 64 00 77 00 61 00 72 00 66 00 70 00 6f 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 3a 00}  //weight: 2, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "\\XMRig Starter\\obj\\Release\\updg" ascii //weight: 1
        $x_1_4 = "hkcmk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_QN_2147728202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.QN!bit"
        threat_id = "2147728202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zlayapanda.do.am/service.update" wide //weight: 1
        $x_1_2 = "Program Files/Microsoft/NetFramework/msdts.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_QK_2147730203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.QK!bit"
        threat_id = "2147730203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://bit.ly/2P3Bz2T" wide //weight: 1
        $x_1_2 = "\\dlhost.exe" wide //weight: 1
        $x_1_3 = "koromn39@gmail.com" wide //weight: 1
        $x_1_4 = "xmr.pool.minergate.com" wide //weight: 1
        $x_1_5 = "McPvTray" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_CoinMiner_R_2147733375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.R"
        threat_id = "2147733375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://huntercode.ru/updater.exe" wide //weight: 1
        $x_1_2 = "\\Miner\\obj\\Release\\Otmivatelnites.pdb" ascii //weight: 1
        $x_1_3 = "\\Microsofter\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_CoinMiner_S_2147734612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.S!bit"
        threat_id = "2147734612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" wide //weight: 1
        $x_1_2 = "ProcessHacker" wide //weight: 1
        $x_1_3 = " -p x -k -v=0 --donate-level=1 -t " wide //weight: 1
        $x_1_4 = "downloadAndExcecute" ascii //weight: 1
        $x_1_5 = "appShortcutToStartup" ascii //weight: 1
        $x_1_6 = "stratum+tcp://xmr.pool.minergate.com:" wide //weight: 1
        $x_1_7 = "minername" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_CoinMiner_T_2147734646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.T!bit"
        threat_id = "2147734646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks.exe" wide //weight: 1
        $x_1_2 = "create /sc " wide //weight: 1
        $x_1_3 = "/mo 1 /tn" wide //weight: 1
        $x_1_4 = "taskmgr" wide //weight: 1
        $x_1_5 = "ProcessHacker" wide //weight: 1
        $x_1_6 = "Task Manager" wide //weight: 1
        $x_1_7 = "AMD" wide //weight: 1
        $x_1_8 = "nvidia" wide //weight: 1
        $x_1_9 = "geforce" wide //weight: 1
        $x_1_10 = "SELECT * FROM Win32_DisplayConfiguration" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_CI_2147735439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.CI"
        threat_id = "2147735439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NetFramework\\BreadcrumbStore\\xmr\\lsass.exe" wide //weight: 1
        $x_1_2 = "http://211.32.127.6:80/ezon/images/img" wide //weight: 1
        $x_1_3 = "fr.minexmr.com:80" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_CoinMiner_CJ_2147735440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.CJ"
        threat_id = "2147735440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://211.112.25.235/ezon/sw/SWFT/Image/user/web/" wide //weight: 1
        $x_1_2 = "AutoScanCrackExe.Properties.tasklist.txt" wide //weight: 1
        $x_1_3 = "http://18.205.168.2/tinnoota/upload/33/1072/config/ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_XB_2147758042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.XB"
        threat_id = "2147758042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 77 00 69 00 6e 00 73 00 65 00 72 00 76 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 48 00 75 00 62 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\Desktop\\Miner\\FULLMINER\\WindowsHub" ascii //weight: 1
        $x_1_4 = "downloadAndExcecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_CoinMiner_AVI_2147762228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AVI!MSR"
        threat_id = "2147762228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Taskmgr" wide //weight: 1
        $x_1_2 = "ProcessHacker" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 72 00 62 00 66 00 69 00 6c 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 [0-21] 73 00 79 00 73 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = ".temp" wide //weight: 1
        $x_1_5 = "\\Windows Update Service.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_AV_2147762646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AV!MSR"
        threat_id = "2147762646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Qkkbal" ascii //weight: 1
        $x_1_2 = "vihansoft.ir" wide //weight: 1
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 72 00 62 00 66 00 69 00 6c 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 [0-15] 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_4 = ".temp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_KSH_2147769241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.KSH!MSR"
        threat_id = "2147769241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vihansoft.ir" wide //weight: 1
        $x_1_2 = "SystemManagement.exe" wide //weight: 1
        $x_1_3 = "WindowsSecurityService.pdb" ascii //weight: 1
        $x_1_4 = "config.json" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ATM_2147781337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ATM!MTB"
        threat_id = "2147781337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "KGiEVdTdB0rzrn9pGzz0mw==" ascii //weight: 5
        $x_5_2 = "QkoTR9PXhbviSVEm2cYxaQ==" ascii //weight: 5
        $x_5_3 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide //weight: 5
        $x_3_4 = "CreateSubKey" ascii //weight: 3
        $x_3_5 = "jrsoilscjyv" ascii //weight: 3
        $x_3_6 = "+2ZJqaN7cCKZJayunaqoY0t4JXe4SCvoyWXklM2of/5gaPK+G4R6xU9bp55ItU9+" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ADA_2147781872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ADA!MTB"
        threat_id = "2147781872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "[InternetShortcut]" ascii //weight: 3
        $x_3_2 = "/C ping 127.0.0.1 -n 2 && taskmgr &&" ascii //weight: 3
        $x_3_3 = "cfg.txt" ascii //weight: 3
        $x_3_4 = "\\AppData\\Roaming\\Sysfiles\\" ascii //weight: 3
        $x_3_5 = "-p x -k -v=0 --donate-level=1 -t" ascii //weight: 3
        $x_3_6 = "ProcessHacker" ascii //weight: 3
        $x_3_7 = "downloadAndExcecute" ascii //weight: 3
        $x_3_8 = "win32_logicaldisk.deviceid=" ascii //weight: 3
        $x_3_9 = "?hwid=" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_S_2147783884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.S!ibt"
        threat_id = "2147783884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "schtasks /create /tn \\" ascii //weight: 4
        $x_4_2 = "/st 00:00 /du 9999:59 /sc once /ri 1 /f" ascii //weight: 4
        $x_4_3 = {63 00 68 00 6f 00 69 00 63 00 65 00 20 00 2f 00 43 00 20 00 59 00 20 00 2f 00 4e 00 20 00 2f 00 44 00 20 00 59 00 20 00 2f 00 54 00 [0-6] 26 00 20 00 44 00 65 00 6c 00}  //weight: 4, accuracy: Low
        $x_4_4 = {63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 [0-6] 26 20 44 65 6c}  //weight: 4, accuracy: Low
        $x_1_5 = "--max-cpu-usage" wide //weight: 1
        $x_1_6 = "xmrig" wide //weight: 1
        $x_1_7 = "stratum" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 1 of ($x_1_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CoinMiner_MA_2147807604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MA!MTB"
        threat_id = "2147807604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://185.172.128.11" ascii //weight: 1
        $x_1_2 = "11eaf172-11dc-4522-b3ae-b972785de2db" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MA_2147807604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MA!MTB"
        threat_id = "2147807604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de}  //weight: 5, accuracy: Low
        $x_1_2 = "Minesweeper_WindowsFormsApp" ascii //weight: 1
        $x_1_3 = "get_DarkRed" ascii //weight: 1
        $x_1_4 = "get_IsHidden" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MA_2147807604_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MA!MTB"
        threat_id = "2147807604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 07 1f 64 73 ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 09 20 00 01 00 00 6f ?? ?? ?? 0a 09 17 6f ?? ?? ?? 0a 09 08 1f 10 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 13 04 73 ?? ?? ?? 0a 13 05 11 05 11 04 17 73 ?? ?? ?? 0a 13 06 11 06 02 16 02 8e 69 6f ?? ?? ?? 0a 11 06 6f ?? ?? ?? 0a de}  //weight: 1, accuracy: Low
        $x_1_2 = "GetFolderPath" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "set_KeySize" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MB_2147807605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MB!MTB"
        threat_id = "2147807605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 1f 10 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 20 ?? ?? ?? ?? 2b 00 28 ?? ?? ?? 2b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 24 07 06 1f 10 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 20 ?? ?? ?? ?? 2b 00 28 ?? ?? ?? 2b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 20 ?? ?? ?? ?? 38 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {61 25 13 07 19 5e 45 03 00 00 00 df ff ff ff 02 00 00 00 19 00 00 00 2b 17 11 04 6f ?? ?? ?? 0a 11 07 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 2b cb}  //weight: 1, accuracy: Low
        $x_1_3 = "ResumeThread" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
        $x_1_5 = "UnmapViewOfSection" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "Kill" ascii //weight: 1
        $x_1_8 = "CreateEncryptor" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MB_2147807605_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MB!MTB"
        threat_id = "2147807605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://185.172.128.11" ascii //weight: 5
        $x_3_2 = "/c schtasks /create /f /sc MINUTE /mo 3 /RL HIGHEST /tn" wide //weight: 3
        $x_1_3 = "/create /sc MINUTE /mo 3 /tn" wide //weight: 1
        $x_1_4 = "/zima.php?mine=XMR" wide //weight: 1
        $x_1_5 = "@echo off" wide //weight: 1
        $x_1_6 = "timeout 3 > NUL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MD_2147809189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MD!MTB"
        threat_id = "2147809189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 08 61 13 11 11 06 11 0b 11 11 20 ff 00 00 00 5f d2 9c 11 06 11 0b 17 58 11 11 20 00 ff 00 00 5f 1e 64 d2 9c 11 06 11 0b 18 58 11 11 20 00 00 ff 00 5f 1f 10 64 d2 9c 11 06 11 0b 19 58 11 11 20 00 00 00 ff 5f 1f 18 64 d2 9c 11 0a 17 58 13 0a 11 0a 11 05 3f bf fc ff ff 11 06 0d 14 13 06 09 8e 69 1e 5b 13 12 09 73 ?? ?? ?? 0a 73 ?? ?? ?? 06 13 13 16 13 14}  //weight: 1, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "FlushFinalBlock" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_8 = "CryptoStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RPW_2147818047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RPW!MTB"
        threat_id = "2147818047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tempload" wide //weight: 1
        $x_1_2 = "xmrig" wide //weight: 1
        $x_1_3 = "minernode" wide //weight: 1
        $x_1_4 = "minerno.de" wide //weight: 1
        $x_1_5 = "configgen.php" wide //weight: 1
        $x_1_6 = "wallet" wide //weight: 1
        $x_1_7 = "misterballs" wide //weight: 1
        $x_1_8 = "api.ipify.org" wide //weight: 1
        $x_1_9 = "IndMiner" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ME_2147818453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ME!MTB"
        threat_id = "2147818453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 16 0b 16 0c 2b 27 02 08 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 06 07 25 17 58 0b 91 61 d2 81 ?? ?? ?? 01 07 06 8e 69 33 02 16 0b 08 17 58 0c 08 02 8e 69 32 d3 02 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "Decrypt" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "RandomPassNew" ascii //weight: 1
        $x_1_6 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PA13_2147819841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PA13!MTB"
        threat_id = "2147819841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--url pool.hashvault.pro:80" ascii //weight: 1
        $x_1_2 = "--pass XMR --donate-level 1 --tls --tls-fingerprint" ascii //weight: 1
        $x_1_3 = "tlmana" ascii //weight: 1
        $x_1_4 = "ConsentPromptBehaviorAdmin" ascii //weight: 1
        $x_1_5 = "PromptOnSecureDesktop" ascii //weight: 1
        $x_1_6 = "kill" ascii //weight: 1
        $x_1_7 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_8 = "Software\\Classes\\mscfile\\Shell\\Open\\command" ascii //weight: 1
        $x_1_9 = "miner.exe" ascii //weight: 1
        $x_1_10 = "ProcessHacker" ascii //weight: 1
        $x_1_11 = "OpenHardwareMonitor" ascii //weight: 1
        $x_1_12 = "NumberOfLogicalProcessors" ascii //weight: 1
        $x_1_13 = "SELECT * FROM Win32_VideoController" ascii //weight: 1
        $x_1_14 = "schtasks.exe /create /f /sc MINUTE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RPI_2147830265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RPI!MTB"
        threat_id = "2147830265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "us-eth.2miners.com:2020" wide //weight: 1
        $x_1_2 = "0x298a98736156cdffdfaf4580afc4966904f1e12e" wide //weight: 1
        $x_1_3 = "-retrydelay" wide //weight: 1
        $x_1_4 = "-coin eth" wide //weight: 1
        $x_1_5 = "-pool" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NXW_2147830935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NXW!MTB"
        threat_id = "2147830935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7f 9d a2 35 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 78 00 00 00 0c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "WindowsFormsApp3.Form1.resources" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp3.exe" ascii //weight: 1
        $x_1_4 = "CreateProcess" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "ZwUnmapViewOfSection" ascii //weight: 1
        $x_1_8 = "CreateRemoteThread" ascii //weight: 1
        $x_1_9 = "ResumeThread" ascii //weight: 1
        $x_1_10 = "CloseHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_AH_2147832025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AH!MTB"
        threat_id = "2147832025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 08 11 08 11 07 16 73 ?? ?? ?? 0a 13 09 09 8e 69 8d ?? ?? ?? 01 13 0a 11 09 11 0a 16 11 0a 8e 69 6f ?? ?? ?? 0a 13 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "_5xg3H2H6cFNjErC0WeUXp3fLN0m" ascii //weight: 1
        $x_1_3 = "$d45ad80b-f521-49c4-8aea-bfca2f21b9bf" ascii //weight: 1
        $x_1_4 = "Decrypt" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDA_2147834166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDA!MTB"
        threat_id = "2147834166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BybMz09Uy+/rrL7X0lUL5w==" wide //weight: 1
        $x_1_2 = "5z74wjnRED2YiTAPVDc8f8xOlXu4LXDCVlan9tuuuDsoS+8urZ+3OG4ljPqSMpTkRykBUKwnM12f8xfX9q5LDw==" wide //weight: 1
        $x_1_3 = "q0tFBVhOX2QgDCie00qrsw==" wide //weight: 1
        $x_1_4 = "pJXcR31GzX5MED5q1zvJBQ==" wide //weight: 1
        $x_1_5 = "kernel32" ascii //weight: 1
        $x_1_6 = "VirtualProtect" ascii //weight: 1
        $x_1_7 = "LoadLibrary" ascii //weight: 1
        $x_1_8 = "GetProcAddress" ascii //weight: 1
        $x_1_9 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "hviylthpmrfczw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ABJ_2147834831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ABJ!MTB"
        threat_id = "2147834831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IyAgID09PT09PT09PT09PT09PT09DQojICAg" ascii //weight: 1
        $x_1_2 = "5OZXQuV2ViQ2xpZW50XTo6bmV3KCkNCg0KUmVtb3ZlLWl0Z" ascii //weight: 1
        $x_1_3 = "3RhcnQtU2xlZXAgLVNlY29uZHMgNCksKFN0YXJ0LVB" ascii //weight: 1
        $x_1_4 = "Y3NjIiAtZWEgU2lsZW50bHlDb250aW51ZSkgLWVxI" ascii //weight: 1
        $x_1_5 = "c2lvbnMvOTkudHh0Ig0KJGxpbmtleGUgPSAiaHR0cDovL2NvLmx0c21heC5jb20vcGgvcGhmaWxlcy9zc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDB_2147835441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDB!MTB"
        threat_id = "2147835441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nLock" ascii //weight: 1
        $x_1_2 = "2d9800bc-2815-493b-88f5-71895f492d78" ascii //weight: 1
        $x_1_3 = "bkxvY2sl" wide //weight: 1
        $x_1_4 = "PublicKeyToken=" wide //weight: 1
        $x_1_5 = "DESCryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "DeflateStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RPH_2147835526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RPH!MTB"
        threat_id = "2147835526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rustforall.net" wide //weight: 1
        $x_1_2 = "MsMpEn.exe" wide //weight: 1
        $x_1_3 = "restarting mine after 1min" wide //weight: 1
        $x_1_4 = "nvidia" wide //weight: 1
        $x_1_5 = "geforce" wide //weight: 1
        $x_1_6 = "quadro" wide //weight: 1
        $x_1_7 = "radeon" wide //weight: 1
        $x_1_8 = "objShell.Run" wide //weight: 1
        $x_1_9 = "Explorer\\StartupApproved\\StartupFolder" wide //weight: 1
        $x_1_10 = "/C choice /C Y /N /D Y /T 2 & Del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NC_2147836559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NC!MTB"
        threat_id = "2147836559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 96 04 00 70 80 ?? ?? ?? 04 20 01 00 00 00 16 39 ?? ?? ?? ff 26 38 78 ff ff ff 72 ?? ?? ?? 70 80 01 00 00 04 38 d6 ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "nimqeFAH8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NC_2147836559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NC!MTB"
        threat_id = "2147836559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 5e 00 00 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f 56 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "http://185.172.128.11/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NC_2147836559_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NC!MTB"
        threat_id = "2147836559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 28 00 00 0a 6f ?? ?? 00 0a 13 04 73 ?? ?? 00 0a 13 05 11 05 11 04 28 ?? ?? 00 06 73 ?? ?? 00 0a 13 06 00 11 06 02 28 ?? ?? 00 06 02 8e 69 6f ?? ?? 00 0a 00 11 06 6f ?? ?? 00 0a 00 11 05 6f ?? ?? 00 0a 13 07 de 4e}  //weight: 5, accuracy: Low
        $x_5_2 = {28 1b 00 00 0a 0a 73 ?? 00 00 0a 0b 06 02 6f ?? 00 00 0a 0c 08 14 fe 01 13 05 11 05 2d 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NC_2147836559_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NC!MTB"
        threat_id = "2147836559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 11 00 00 04 28 ?? ?? ?? 0a 0a 25 06 6f ?? ?? ?? 0a 6a 6f ?? ?? ?? 0a 25 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 25 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 25 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "C3554254475.C1255198513.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NRF_2147837017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NRF!MTB"
        threat_id = "2147837017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {03 6f 2a 00 00 0a 2c 32 07 6f ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 08 09 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_3 = "WindowsBuiltInRole" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_GBS_2147837399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.GBS!MTB"
        threat_id = "2147837399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 12 11 13 9a 13 04 11 04 28 ?? ?? ?? 06 13 05 07 72 ?? ?? ?? 70 11 05 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 2d 17 09 72 ?? ?? ?? 70 28 ?? ?? ?? 06 11 05 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 13 17 58 13 13 11 13 11 12 8e 69}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_GCD_2147838029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.GCD!MTB"
        threat_id = "2147838029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "I_LOVE_HENTAI" ascii //weight: 1
        $x_1_2 = "txLLvDRNjE37rgOTPf" ascii //weight: 1
        $x_1_3 = "f5PUeQybCOGRrAncQS" ascii //weight: 1
        $x_1_4 = "bEUfMjp4nvhL7Xi2MW" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_CoinMiner_AC_2147838076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AC!MTB"
        threat_id = "2147838076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 88 03 00 04 13 00 7e 89 03 00 04 7e 8a 03 00 04 7e 8b 03 00 04 61 7e 8c 03 00 04 40 0d 00 00 00 7e 42 00 00 04 13 00 7e 8d 03 00 04 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_AC_2147838076_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AC!MTB"
        threat_id = "2147838076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 22 11 23 9a 13 24 00 11 24 6f ?? ?? ?? 0a 11 21 6f ?? ?? ?? 0a fe 01 16 fe 01 13 25 11 25 2c 05 00 16 13 08 00 00 11 23 17 58 13 23 11 23 11 22 8e 69 32 cb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_EC_2147838089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.EC!MTB"
        threat_id = "2147838089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vaflya123/Valyak" wide //weight: 1
        $x_1_2 = "AZ AM BY RU GE KZ KG MD TJ TM UZ UA" wide //weight: 1
        $x_1_3 = "DllImportAttribute" ascii //weight: 1
        $x_1_4 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_5 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "DownloadData" ascii //weight: 1
        $x_1_8 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_EC_2147838089_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.EC!MTB"
        threat_id = "2147838089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Desktop\\NO.txt" ascii //weight: 1
        $x_1_2 = "/create /sc MINUTE /mo 1 /tn \"Dragon\" /tr" ascii //weight: 1
        $x_1_3 = "\\AppData\\dragon.exe" ascii //weight: 1
        $x_1_4 = "\\AppData\\xmrig.exe" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "\\AppData\\logs\\wallets\\" ascii //weight: 1
        $x_1_7 = "\\AppData\\logs\\chrome extension wallets\\" ascii //weight: 1
        $x_1_8 = "Bytecoin" ascii //weight: 1
        $x_1_9 = "testonata.free.beeceptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MBP_2147838134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MBP!MTB"
        threat_id = "2147838134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Fy\\fy_guard.data" wide //weight: 1
        $x_1_2 = {87 65 f6 4e 22 4e 31 59 0c ff f7 8b 73 51 40 67 d2 6b 0e 54 cd 91 b0 65 2f 54 a8 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_SPQP_2147838215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.SPQP!MTB"
        threat_id = "2147838215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {7e ce 07 00 04 7e cf 07 00 04 7e d0 07 00 04 61 7e d1 07 00 04 40 0d 00 00 00 7e 43 00 00 04 13 16 7e d2 07 00 04 58 00 6a 58 13 05 11 04 7e 45 00 00 04 13 17 7e d3 07 00 04 7e d4 07 00 04 7e d5 07 00 04 61 7e d6 07 00 04 40 0d 00 00 00 7e 43 00 00 04 13 17 7e d7 07 00 04 58 00 6f ?? ?? ?? 0a 11 05 28 ?? ?? ?? 0a 11 06 28 ?? ?? ?? 0a 3a 82 ff ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_SPQP_2147838215_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.SPQP!MTB"
        threat_id = "2147838215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 cb 09 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 cb 09 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 34 00 00 0a 0d 09 02 16 02 8e 69}  //weight: 10, accuracy: Low
        $x_2_2 = "phniphpcsivjtyycgcljfpha" ascii //weight: 2
        $x_2_3 = "evbapzhonuwuhieu" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDD_2147838226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDD!MTB"
        threat_id = "2147838226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "splwow32" ascii //weight: 1
        $x_1_2 = "-whatt" wide //weight: 1
        $x_1_3 = "-extdummt" wide //weight: 1
        $x_1_4 = "IyAgID09PT09PT09PT09PT09PT09DQojICAgfCAgICAgICAgICAgICAgIHwNCiMgICB8IFN0YXJ0aW5nIC4uLiAgfA0KIyAgIHwgICA" wide //weight: 1
        $x_1_5 = "GetFileType" ascii //weight: 1
        $x_1_6 = "GetStdHandle" ascii //weight: 1
        $x_1_7 = "MB_GetString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDE_2147838227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDE!MTB"
        threat_id = "2147838227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "275ad438-f90d-4e32-a492-5e1b5c7ae198" ascii //weight: 1
        $x_1_2 = "kubastick's Bitcoin CPU miner" ascii //weight: 1
        $x_1_3 = "Bitcoin CPU miner by Jakub Tomana" wide //weight: 1
        $x_1_4 = "3FMiVhp7V9VxSbj4wcwfdZ9jSPGKfJQdek" wide //weight: 1
        $x_1_5 = "mine.p2pool.com:9332" wide //weight: 1
        $x_1_6 = "ImTestingBitcoinMinerDoNotWorry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ARA_2147838277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ARA!MTB"
        threat_id = "2147838277"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 09 02 09 91 06 61 03 08 91 61 28 ?? ?? ?? 0a 9c 08 03 8e 69 17 59 33 04 16 0c 2b 04 08 17 58 0c 09 17 58 0d 09 02 8e 69 17 59 31 d3}  //weight: 5, accuracy: Low
        $x_5_2 = "etc.2miners.com:1010" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NVC_2147838499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NVC!MTB"
        threat_id = "2147838499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 3e 00 00 0a 13 05 09 11 05 7e ?? ?? 00 04 13 09 7e ?? ?? 00 04 7e ?? ?? 00 04 7e ?? ?? 00 04 61 7e ?? ?? 00 04 40 ?? ?? 00 00 7e ?? ?? 00 04 13 09 7e ?? ?? 00 04 58 00 11 05 8e 69 6f ?? ?? 00 0a 09 6f ?? ?? 00 0a 07 6f ?? ?? 00 0a 13 06 28 ?? ?? 00 0a 11 06 7e ?? ?? 00 04 13 0a 7e ?? ?? 00 04 7e ?? ?? 00 04 7e ?? ?? 00 04 61 7e ?? ?? 00 04 40 ?? ?? 00 00 7e ?? ?? 00 04 13 0a 7e ?? ?? 00 04 58 00 11 06 8e 69 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp3.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_GCV_2147838515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.GCV!MTB"
        threat_id = "2147838515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 14 11 15 9a 13 0e 11 0c 11 0e 16 9a 6f ?? ?? ?? 0a 2d 70 11 0e 17 9a 72 ?? ?? ?? ?? 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 2d 19 11 0e 17 9a 72 ?? ?? ?? ?? 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 2c 46 11 0b 2c 42 11 0e 17 9a 72 ?? ?? ?? ?? 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 2d 04 11 0a 2b 02}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_SPQC_2147838630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.SPQC!MTB"
        threat_id = "2147838630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 72 00 01 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 8d 16 00 00 01 13 0f 11 0f 16 1f 20 9d 11 0f 6f ?? ?? ?? 0a 13 10 16 13 11 2b 28 11 10 11 11 9a 13 07 11 07 28 ?? ?? ?? 06 13 08 11 08 28 ?? ?? ?? 0a 2d 09}  //weight: 2, accuracy: Low
        $x_1_2 = "ocpfhvabfhplyxjg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MBAK_2147838631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MBAK!MTB"
        threat_id = "2147838631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6d 00 79 00 6a 00 67 00 35 00 00 0b 6a 00 6d 00 6d 00 72 00 35}  //weight: 1, accuracy: High
        $x_1_3 = "snvood8" wide //weight: 1
        $x_1_4 = "Sgffg5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_GDD_2147839031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.GDD!MTB"
        threat_id = "2147839031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 16 11 04 8e b7 6f ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 17 6f ?? ?? 00 0a 08 6f ?? ?? ?? 0a 02 16 02 8e b7 6f ?? ?? ?? 0a 0d 09 0a de 0c de 0a}  //weight: 10, accuracy: Low
        $x_1_2 = "ToBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_BAN_2147839339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.BAN!MTB"
        threat_id = "2147839339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 02 7e ?? 00 00 04 13 0e 7e ?? 0e 00 04 7e ?? 0e 00 04 7e ?? 0e 00 04 61 7e ?? 0e 00 04 40 0d 00 00 00 7e ?? 00 00 04 13 0e 7e ?? 0e 00 04 58 00 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a dd}  //weight: 2, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "FlushFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_GDN_2147839604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.GDN!MTB"
        threat_id = "2147839604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PXNUbL7fmWxhR3f3Uf" ascii //weight: 1
        $x_1_2 = "vft0kIBQ64LMoc9fxw" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NEAA_2147839718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NEAA!MTB"
        threat_id = "2147839718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 02 7b 37 00 00 04 61 0a 02 02 7b 37 00 00 04 1d 28 be 00 00 06 06 61 7d 37 00 00 04 06 2a}  //weight: 10, accuracy: High
        $x_2_2 = "activation.php?code=" wide //weight: 2
        $x_2_3 = "Mozilla/4.0" wide //weight: 2
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "Banned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NDC_2147839728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NDC!MTB"
        threat_id = "2147839728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 7c 00 00 04 28 ?? 00 00 0a 0a 06 2c 0d 00 7e ?? 00 00 04 28 ?? 00 00 0a 00 00 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 0a 00 02 16 28 ?? 00 00 0a 00 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "MS41 ECU Portal" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NKC_2147839766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NKC!MTB"
        threat_id = "2147839766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 0a 00 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 73 ?? ?? 00 0a 25 6f ?? ?? 00 0a 16 6a 6f ?? ?? 00 0a 25 25 6f ?? ?? 00 0a 6f ?? ?? 00 0a 69 6f ?? ?? 00 0a 13 05}  //weight: 5, accuracy: Low
        $x_1_2 = "kLjw4iIsCLsZtxc4lksN0j" ascii //weight: 1
        $x_1_3 = "add_ResourceResolve" ascii //weight: 1
        $x_1_4 = "RemoveReg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NCM_2147840062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NCM!MTB"
        threat_id = "2147840062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 41 00 00 0a 7e ?? ?? 00 04 13 0d 7e ?? ?? 00 04 7e ?? ?? 00 04 7e ?? ?? 00 04 61 7e ?? ?? 00 04 40 ?? ?? 00 00 7e ?? ?? 00 04 13 0d 7e ?? ?? 00 04 58 00 73 ?? ?? 00 0a 13 05 11 05 02 7e ?? ?? 00 04 13 0e 7e ?? ?? 00 04 7e ?? ?? 00 04 7e ?? ?? 00 04 61 7e ?? ?? 00 04 40 ?? ?? 00 00 7e ?? ?? 00 04 13 0e 7e ?? ?? 00 04 58 00 02 8e 69 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {39 16 00 00 00 07 7e ?? ?? 00 04 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 38 ?? ?? 00 00 07 7e ?? ?? 00 04 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_3 = "WindowsFormsApp3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDF_2147840149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDF!MTB"
        threat_id = "2147840149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sip12213778442232847664" ascii //weight: 1
        $x_1_2 = "-whatt" wide //weight: 1
        $x_1_3 = "-extdummt" wide //weight: 1
        $x_1_4 = "JGxvZ28gPSAnLl9fICAgX18uICBfX19fX19fX19fICAgX19fIC5fX19fX19fX19fXy4gX19fX19fXyAgX18NCnwgIFwgfCAgfCB8ICA" wide //weight: 1
        $x_1_5 = "GetFileType" ascii //weight: 1
        $x_1_6 = "GetStdHandle" ascii //weight: 1
        $x_1_7 = "WriteConsoleOutputW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ACM_2147841226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ACM!MTB"
        threat_id = "2147841226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 7b 5b 01 00 04 6a 58 06 20 ?? ?? ?? 00 64 0a e0 06 20 ?? ?? ?? 2f 5c 0a 47 02 02 7b 5b 01 00 04 06}  //weight: 2, accuracy: Low
        $x_1_2 = "RealUI-Installer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ACM_2147841226_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ACM!MTB"
        threat_id = "2147841226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 2b 27 11 05 11 06 9a 13 07 00 11 07 73 17 00 00 0a 13 08 11 08 6f ?? ?? ?? 0a 13 09 11 09 2c 02 16 0a 00 11 06 17 58 13 06 11 06 11 05 8e 69 32 d1}  //weight: 2, accuracy: Low
        $x_1_2 = "xumre" wide //weight: 1
        $x_1_3 = "zumlr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ACM_2147841226_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ACM!MTB"
        threat_id = "2147841226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 2b 2b 30 1b 2c f9 1e 2c f6 2b 2b 2b 30 2b 31 2b 36 75 01 00 00 1b 2b 36 19 2c 0f 16 2d e1 2b 31 16 2b 31 8e 69 28 ?? ?? ?? 0a 07 2a 28 ?? ?? ?? 06 2b ce 0a 2b cd 28 ?? ?? ?? 0a 2b ce 06 2b cd 6f ?? ?? ?? 0a 2b c8 28 ?? ?? ?? 06 2b c3 0b 2b c7 07 2b cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_EAC_2147842116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.EAC!MTB"
        threat_id = "2147842116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 16 0c 07 8e 69 17 59 0d 38 ?? 00 00 00 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 32 e4 07 13 05 dd ?? 00 00 00 26 de b4}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ACI_2147842155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ACI!MTB"
        threat_id = "2147842155"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UX_Login_Insta.exe" wide //weight: 2
        $x_2_2 = "flash_lightning_ray_icon_231454" wide //weight: 2
        $x_2_3 = "vector-colorful-holographic-gradient-background-design" wide //weight: 2
        $x_1_4 = "FormData.cs" wide //weight: 1
        $x_1_5 = "UNIX LAUNCHER" wide //weight: 1
        $x_1_6 = "IsDebuggerPresent" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDH_2147843066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDH!MTB"
        threat_id = "2147843066"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spark Activator" ascii //weight: 1
        $x_1_2 = "Qo8G0gT4e2kMtwUd23" ascii //weight: 1
        $x_1_3 = "rFRSe3AasjnoPSJ7j3" ascii //weight: 1
        $x_1_4 = "dmaqcwdnstnmepgl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NCD_2147844511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NCD!MTB"
        threat_id = "2147844511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {18 63 d4 8d 27 00 00 01 13 04 11 0e 20 ?? ?? ?? 28 5a 20 cb 8d df 3c 61 38 ?? ?? ?? ff 11 0e 20 60 72 51 6c 5a 20 ?? ?? ?? 18 61 38 c3 fd ff ff 06 8e 69 1a 58}  //weight: 5, accuracy: Low
        $x_1_2 = "Windows Write" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MBDO_2147845309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MBDO!MTB"
        threat_id = "2147845309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4D5A9))3)))04)))[[[[[[[[))B8)))))))4" ascii //weight: 1
        $x_1_2 = ")08))))E1[[BA0E)B409CD21B8014CCD21546869732070726[[6772616D" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MBDP_2147845338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MBDP!MTB"
        threat_id = "2147845338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 48 08 00 70 72 cb 01 00 70 28 ?? 00 00 06 72 4c 08 00 70 72 52 08 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = {11 02 11 04 18 6f ?? 00 00 0a 20 ?? 02 00 00 28 ?? 00 00 06 13 06 38 ?? ?? ?? ff 02 7b ?? 00 00 04 1f 25 1f 17 73 ?? 00 00 0a 6f ?? 00 00 0a 38 ?? ?? ?? ff 02 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MBDS_2147845428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MBDS!MTB"
        threat_id = "2147845428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 72 21 05 00 70 72 25 05 00 70 6f ?? 00 00 0a 72 2b 05 00 70 72 31 05 00 70 6f ?? 00 00 0a 0b 73 00 01 00 0a 0c 16 0d 2b 23 00 07 09 18 6f ?? 01 00 0a 20 03 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NHI_2147845666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NHI!MTB"
        threat_id = "2147845666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 17 00 00 0a 0b 72 ?? ?? 00 70 0c 73 ?? ?? 00 0a 0d 09 07 72 ?? ?? 00 70 08 28 ?? ?? 00 0a 6f ?? ?? 00 0a 00 09 28 1b 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "GM.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_SPH_2147846053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.SPH!MTB"
        threat_id = "2147846053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 17 00 00 04 28 ?? ?? ?? 0a 72 09 03 00 70 28 ?? ?? ?? 0a 80 0c 00 00 04 7e 0c 00 00 04 6f ?? ?? ?? 0a 16 9a 7e 0d 00 00 04 73 52 00 00 0a 80 0e 00 00 04 18 17 1c 73 53 00 00 0a 80 0b 00 00 04 7e 0b 00 00 04 7e 0e 00 00 04 14 fe 06 14 00 00 06 73 54 00 00 0a 14 6f ?? ?? ?? 0a 26 de 08}  //weight: 1, accuracy: Low
        $x_1_2 = "rootbossko.duckdns.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NHC_2147846353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NHC!MTB"
        threat_id = "2147846353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 46 00 20 0c 00 00 00 fe ?? ?? 00 9c 20 ?? ?? ?? 00 38 ?? ?? ?? ff 11 72 11 61 11 14 58 11 28 11 3b 5f 11 71 1f 1f 5f 64 d2 9c 20 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "WriteAllBytes" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NCI_2147848623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NCI!MTB"
        threat_id = "2147848623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 26 00 00 0a 0c 06 28 ?? 00 00 06 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 28 ?? 00 00 06 08 6f ?? 00 00 0a 26}  //weight: 5, accuracy: Low
        $x_1_2 = "UltraISO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NCI_2147848623_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NCI!MTB"
        threat_id = "2147848623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 e0 13 05 16 13 06 1f 18 58 11 04 58 13 07 20 ?? ?? ?? a8 13 08 11 17 20 ?? ?? ?? 65 5a 20 ?? ?? ?? f8 61 38 ?? ?? ?? ff 20 ?? ?? ?? 97 13 0a 11 17 20 ?? ?? ?? 50 5a 20 ?? ?? ?? a8 61 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "WinMedia.WinMedia_" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDJ_2147851240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDJ!MTB"
        threat_id = "2147851240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3b029c37-44b8-422a-9d39-c7e155100fa5" ascii //weight: 1
        $x_1_2 = "efwreth66" ascii //weight: 1
        $x_1_3 = "ReadBroadcaster" ascii //weight: 1
        $x_1_4 = "Proxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_AYC_2147852735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.AYC!MTB"
        threat_id = "2147852735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 07 11 05 58 17 6f ?? ?? ?? 0a 72 a0 c1 00 70 02 7b 09 00 00 04 28 ?? ?? ?? 0a 73 22 00 00 0a 7a 09 11 06 6e 11 04 17 58 1e 5a 11 05 1b 5a 59 1b 59 1f 3f 5f 62 60 0d 11 05 17 58 13 05 11 05 08 32 9e}  //weight: 2, accuracy: Low
        $x_1_2 = "\\Example.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PSUO_2147852738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PSUO!MTB"
        threat_id = "2147852738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 20 e0 7d 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 06 20 04 00 00 00 38 42 ff ff ff 00 11 02 11 09 17 73 0f 00 00 0a 13 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NCR_2147890302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NCR!MTB"
        threat_id = "2147890302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 00 01 00 00 6f ?? ?? 00 0a 11 05 17 6f ?? ?? 00 0a 11 05 0b 03 2d 1f 07 06 1f 10 6f ?? ?? 00 0a 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = {72 63 31 00 70 28 ?? ?? 00 06 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 6f ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 1f 18 6f ?? ?? 00 0a 14 19 8d ?? ?? 00 01 0a 06 16 02 a2 06 17 03 a2 06 18 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PSXY_2147891525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PSXY!MTB"
        threat_id = "2147891525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 72 01 00 00 70 73 05 00 00 0a 0b 72 39 00 00 70 73 05 00 00 0a 0c 06 07 72 77 00 00 70 6f 06 00 00 0a 06 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_SPAP_2147892568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.SPAP!MTB"
        threat_id = "2147892568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 17 6f ?? ?? ?? 0a 11 06 0c 03 2d 11 08 07 1f 10 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 2b 0f 08 07 1f 10 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 73 2f 00 00 0a 13 04 11 04 09 17 73 30 00 00 0a 13 05}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_KAD_2147892850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.KAD!MTB"
        threat_id = "2147892850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 9a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 2c 09 07 17 58 0b 07 17 31 01 2a 11 04 17 58 13 04 11 04 09 8e 69 32 d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_KAA_2147896235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.KAA!MTB"
        threat_id = "2147896235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 11 05 02 11 05 91 06 61 08 09 91 61 b4 9c 09 03 6f ?? 00 00 0a 17 da 33 04 16 0d 2b 04 09 17 d6 0d 11 05 17 d6 13 05 11 05 11 06 31 d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_SB_2147896359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.SB!MTB"
        threat_id = "2147896359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_2 = "api.ipify.org" ascii //weight: 1
        $x_1_3 = "51.75.36.184" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "schtasks.exe" ascii //weight: 1
        $x_1_6 = "/create /sc MINUTE /mo 1 /tn" ascii //weight: 1
        $x_1_7 = "ToString" ascii //weight: 1
        $x_1_8 = "\\Windows Folder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_KAF_2147896422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.KAF!MTB"
        threat_id = "2147896422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://154.53.160.245" wide //weight: 1
        $x_1_2 = {41 00 70 00 70 00 44 00 61 00 74 00 61 00 00 3f 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00}  //weight: 1, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ABJA_2147896475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ABJA!MTB"
        threat_id = "2147896475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc}  //weight: 2, accuracy: Low
        $x_1_2 = "cgxkglqad" wide //weight: 1
        $x_1_3 = "srprcfaxbveorugc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_ABFJ_2147896495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.ABFJ!MTB"
        threat_id = "2147896495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0d 09 02 16 02 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a de 0a 09 2c 06 09 6f ?? ?? ?? 0a dc 08 6f ?? ?? ?? 0a 13 04 de 14}  //weight: 2, accuracy: Low
        $x_1_2 = "forgrevhtdmvjhxu" wide //weight: 1
        $x_1_3 = "scxyrfdairwpkktdzdgoaoaqbqebuqsr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NBL_2147897305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NBL!MTB"
        threat_id = "2147897305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 a5 dd fe 71 11 0e 20 00 00 00 04 5c 61 16 2e 03 2b 0e 00 20 b6 ?? ?? ?? 20 6f 37 cf df 61 2b 09 7e 4e ?? ?? ?? 8e 1f 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = {06 5f 61 16 33 15 00 06 20 00 20 00 00 5a 20 79 02 00 00 33 06 38 da 00 00 00 00 06 20 70 92 00 00 5a 20 84 15 00 00 61 16 2e 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RDK_2147897422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RDK!MTB"
        threat_id = "2147897422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 03 04 6f 37 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = {02 03 04 73 35 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_3 = {02 03 6f 34 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PSNC_2147897587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PSNC!MTB"
        threat_id = "2147897587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 01 00 00 02 28 14 00 00 0a 6f 18 00 00 0a 25 6f 0e 00 00 0a 0a 06 6f 37 00 00 0a 16 31 0d 06 16 6f 0f 00 00 0a 1f 3c fe 01 2b 01 16 0b 28 19 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PTDH_2147898306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PTDH!MTB"
        threat_id = "2147898306"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e c0 5d 00 04 28 ?? 01 00 06 28 ?? 00 00 06 28 ?? 01 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PSCD_2147899335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PSCD!MTB"
        threat_id = "2147899335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 ac 04 00 70 28 1e 00 00 0a 72 af 06 00 70 6f 1f ?? ?? ?? 1f 64 73 20 ?? ?? ?? 1f 10 6f 21 ?? ?? ?? 0a 28 22 ?? ?? ?? 0b 73 23 ?? ?? ?? 0c 08 03 2d 18 07 06 28 1e ?? ?? ?? 72 f1 06 00 70 6f 1f ?? ?? ?? 6f 24 ?? ?? ?? 2b 16 07 06 28 1e ?? ?? ?? 72 f1 06 00 70 6f 1f ?? ?? ?? 6f 25 ?? ?? ?? 17 73 26 ?? ?? ?? 0d 09 02 16 02 8e 69 6f 27 ?? ?? ?? 09 6f 28 ?? ?? ?? de 0a 09 2c 06 09 6f 14 ?? ?? ?? dc 08 6f 29 ?? ?? ?? 13 04 de 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PSCE_2147899336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PSCE!MTB"
        threat_id = "2147899336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 e8 07 00 70 28 25 ?? ?? ?? 72 eb 09 00 70 6f 26 ?? ?? ?? 1f 64 73 27 ?? ?? ?? 1f 10 6f 28 ?? ?? ?? 0a 28 29 ?? ?? ?? 0b 73 2a ?? ?? ?? 0c 08 03 2d 18 07 06 28 25 ?? ?? ?? 72 2d 0a 00 70 6f 26 ?? ?? ?? 6f 2b ?? ?? ?? 2b 16 07 06 28 25 ?? ?? ?? 72 2d 0a 00 70 6f 26 ?? ?? ?? 6f 2c ?? ?? ?? 17 73 2d ?? ?? ?? 0d 09 02 16 02 8e 69 6f 2e ?? ?? ?? 09 6f 2f ?? ?? ?? de 0a 09 2c 06 09 6f 13 ?? ?? ?? dc 08 6f 30 ?? ?? ?? 13 04 de 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PSCF_2147899337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PSCF!MTB"
        threat_id = "2147899337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 03 2d 18 07 06 28 1e 00 00 0a 72 19 07 00 70 6f 1f 00 00 0a 6f 24 00 00 0a 2b 16 07 06 28 1e 00 00 0a 72 19 07 00 70 6f 1f 00 00 0a 6f 25 00 00 0a 17 73 26 00 00 0a 0d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NL_2147899702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NL!MTB"
        threat_id = "2147899702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "RogueMarket\\Products\\Rogue Miner V2\\Review Backup\\Er minator\\obj\\Release\\OmegaMiner.pdb" ascii //weight: 4
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "-B --donate-level 1" ascii //weight: 1
        $x_1_4 = "coin monero" ascii //weight: 1
        $x_1_5 = "Active Max CPU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_GPD_2147902174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.GPD!MTB"
        threat_id = "2147902174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "pool.minexmr.com:4444" wide //weight: 5
        $x_5_2 = "monerospelunker.conf" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MC_2147902280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MC!MTB"
        threat_id = "2147902280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "http://185.172.128.11" ascii //weight: 5
        $x_1_2 = "encryptionContext" ascii //weight: 1
        $x_1_3 = "GetCorrectedUtcNowForEndpoint" ascii //weight: 1
        $x_1_4 = "DisableLogging" ascii //weight: 1
        $x_1_5 = "AllowAutoRedirect" ascii //weight: 1
        $x_1_6 = "get_DisableHostPrefixInjection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_KAG_2147902498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.KAG!MTB"
        threat_id = "2147902498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 16 9a 28 ?? 00 00 0a 28 ?? 00 00 06 2c 17 28 ?? 00 00 0a 07 17 9a 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 c1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NA_2147902669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NA!MTB"
        threat_id = "2147902669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 ?? ?? 14 00 04 0e 06 17 59 e0 95 58 0e 05 28 40 37 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_KAJ_2147902912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.KAJ!MTB"
        threat_id = "2147902912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 1f 10 28 ?? 00 00 0a 8d ?? 00 00 01 13 09 02 11 08 1f 14 28 ?? 00 00 0a 11 09 16 11 09 8e 69 28 ?? 00 00 0a 11 04 07 11 08 1f 0c 28 ?? 00 00 0a 6a 58 11 09 11 09 8e 69 16 6a 28 ?? 00 00 06 26 11 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MBYC_2147908017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MBYC!MTB"
        threat_id = "2147908017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 2b dc 03 2b db 1c 2c 11 06 2c 0e 16 2d 0b}  //weight: 1, accuracy: High
        $x_1_2 = "Ytguvxm." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_RM_2147908488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.RM!MTB"
        threat_id = "2147908488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--algo ETCHASH --pool etc.2miners.com:1010 --user 0x1252033cDA72C0AF64B7A03F07d2B81A641F11D4.Worker" wide //weight: 1
        $x_1_2 = "Global\\{E7C608DC-209C-45AE-B7C4-366060FF59B3}" wide //weight: 1
        $x_1_3 = "ServiceNul.exe" wide //weight: 1
        $x_1_4 = "TVqQAAMAAAAEAAAA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_NCE_2147911278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.NCE!MTB"
        threat_id = "2147911278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? ?? 00 04 0e 06 17 59 e0 95 58 0e 05 28 4a 1e 00 06 58}  //weight: 5, accuracy: Low
        $x_1_2 = "nWVAcot9AoqNSFEQA5.6WjyXKh6KK0v95eJSi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_BG_2147924702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.BG!MTB"
        threat_id = "2147924702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {de 0b 07 2c 07 07 6f ?? 00 00 0a 00 dc 00 06 7b 01 00 00 04 72 ?? ?? 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 06}  //weight: 2, accuracy: Low
        $x_1_2 = {2b 0d 00 20 e8 03 00 00 28 ?? 00 00 0a 00 00 17 0c 2b}  //weight: 1, accuracy: Low
        $x_1_3 = "By using You agree mining xmr by using xmrig.exe" wide //weight: 1
        $x_1_4 = "xmrig/xmrig/releases/download/v6.22.0/xmrig-6.22.0-msvc-win64.zip" wide //weight: 1
        $x_1_5 = "4A84Tohq5F8FADrQk3FLpWAm5YB7QJDkA4HQKBbDEU8eKnnw3s82VuJLNkvoFPzATAhEPBxj8pxTJcUXewaE5CxFEHkX9tf" wide //weight: 1
        $x_1_6 = "420c7850e09b7c0bdcf748a7da9eb3647daf8515718f36d9ccfdd6b9ff834b14" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_BH_2147926474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.BH!MTB"
        threat_id = "2147926474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0a 14 0b 02 28 ?? 00 00 0a 0b 17 0a de 08 26 de 05 26 17 0a de 00 07 2c 06 07 6f ?? 00 00 0a 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "Mutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_PLLGH_2147930043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.PLLGH!MTB"
        threat_id = "2147930043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 27 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_BAA_2147945622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.BAA!MTB"
        threat_id = "2147945622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 14 00 00 0a 0a 06 8e 69 8d 17 00 00 01 0b 06 06 8e 69 20 9a 02 00 00 59 07 16 20 4d 01 00 00 28 15 00 00 0a 06 16 07 20 4d 01 00 00 06 8e 69 20 9a 02 00 00 59 28 15 00 00 0a 06 06 8e 69 20 4d 01 00 00 59 07 06 8e 69 20 4d 01 00 00 59 20 4d 01 00 00 28 15 00 00 0a 07 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CoinMiner_MCF_2147946228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CoinMiner.MCF!MTB"
        threat_id = "2147946228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CoinMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 49 37 58 65 73 37 64 63 52 4f 56 30 37 58 64 32 54 57 00 44 53 51 73 74 58 37 4c 68 6a 67 44 49 54 5a 59 76 4e 38 00 71 32 4a 30 52 72 37 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

