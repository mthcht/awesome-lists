rule Trojan_MSIL_Diztakun_A_2147712472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.A!bit"
        threat_id = "2147712472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 3a 00 [0-16] 41 00 6e 00 74 00 69 00 2d 00 56 00 69 00 72 00 75 00 73 00 3a 00 [0-16] 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 3a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 61 6e 00 44 69 73 61 62 6c 65 52 65 67 65 64 69 74 00 44 69 73 61 62 6c 65 4d 53 43 6f 6e 66 69 67}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 70 79 46 72 6f 6d 53 63 72 65 65 6e 00 53 63 72 65 65 6e 53 61 76 65}  //weight: 1, accuracy: High
        $x_1_4 = {06 02 08 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 1b 58 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 08 17 58 0c 08 09 31 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_AZ_2147840099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.AZ!MTB"
        threat_id = "2147840099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 9a 0d 09 75 23 00 00 01 13 04 11 04 2d 36 09 75 39 00 00 01 2c 0a 09 a5 39 00 00 01 13 05 2b 58 09 75 3d 00 00 01 2c 0a 09 a5 3d 00 00 01 13 06 2b 57 09 75 3e 00 00 01 2c 75 09 a5 3e 00 00 01 13 07 2b 5c 06 11 04 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_ARA_2147847411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.ARA!MTB"
        threat_id = "2147847411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "winload.pdb" ascii //weight: 2
        $x_2_2 = "etkontrol" ascii //weight: 2
        $x_2_3 = "C:\\ProgramData\\mtaku" ascii //weight: 2
        $x_2_4 = "C:\\Windows\\winstart.exe" ascii //weight: 2
        $x_2_5 = "C:\\Windows\\akc\\strsdf" ascii //weight: 2
        $x_2_6 = "C:\\ProgramData\\mtaku\\weblist.fatih" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_ADT_2147848816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.ADT!MTB"
        threat_id = "2147848816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 06 07 6f ?? ?? ?? 0a 00 00 de 0b 09 2c 07 09 6f ?? ?? ?? 0a 00 dc 07 28 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 00 07 28 ?? ?? ?? 0a 13 04 11 04 2c 09 00 07 28}  //weight: 2, accuracy: Low
        $x_1_2 = "DisableTaskMgr" wide //weight: 1
        $x_1_3 = "DisableRegistryTools" wide //weight: 1
        $x_1_4 = "Easy-ToolKit.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_CCHT_2147903949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.CCHT!MTB"
        threat_id = "2147903949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "disablewd" ascii //weight: 1
        $x_1_2 = "restartpc" ascii //weight: 1
        $x_1_3 = "shellKill" ascii //weight: 1
        $x_1_4 = "disabletaskmgr" ascii //weight: 1
        $x_1_5 = "CheckDefender" ascii //weight: 1
        $x_1_6 = "DisableAntiSpyware" wide //weight: 1
        $x_1_7 = "DisableBehaviorMonitoring" wide //weight: 1
        $x_1_8 = "DisableRealtimeMonitoring" wide //weight: 1
        $x_1_9 = "DisableIOAVProtection" wide //weight: 1
        $x_1_10 = "DisableScriptScanning" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_SG_2147912187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.SG!MTB"
        threat_id = "2147912187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$68c26db9-e02b-4edf-9239-f1ed60596ca7" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" wide //weight: 1
        $x_1_3 = "excludedownload.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_NS_2147927268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.NS!MTB"
        threat_id = "2147927268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Restrict-Run" wide //weight: 2
        $x_2_2 = "DisableTaskMgr" wide //weight: 2
        $x_1_3 = "lenyanyyds" wide //weight: 1
        $x_1_4 = "ppn/uA/2dZjwwvM3/m7uDw==" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_6 = "jsmhToolChest.5.0B29.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_ND_2147933525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.ND!MTB"
        threat_id = "2147933525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 4b 00 00 0a 08 6f 5a 00 00 0a 0a 06 72 15 08 00 70 07 6f 5b 00 00 0a}  //weight: 3, accuracy: High
        $x_1_2 = "$13aeac73-ea03-415f-b277-8690eeef3a7b" ascii //weight: 1
        $x_1_3 = "OnlineExam.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_AXC_2147948425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.AXC!MTB"
        threat_id = "2147948425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 72 11 00 00 70 6f 18 00 00 0a 00 06 28 19 00 00 0a 26 7e 1a 00 00 0a 72 80 01 00 70 6f 1b 00 00 0a 0b 07 72 f4 01 00 70 17 8c 22 00 00 01 17 6f 1c 00 00 0a 00 7e 1d 00 00 0a 72 12 02 00 70 6f 1b 00 00 0a 0c 08 72 7e 02 00 70 72 8a 02 00 70 17 6f 1c 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "ProcessStartInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Diztakun_EOCS_2147951130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Diztakun.EOCS!MTB"
        threat_id = "2147951130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Diztakun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 04 06 07 ?? ?? ?? ?? ?? 16 73 0c 00 00 0a 13 06 73 0d 00 00 0a 13 07 11 06 11 07 ?? ?? ?? ?? ?? 11 07 ?? ?? ?? ?? ?? 13 08 de 30 11 07 2c 07 11 07 ?? ?? ?? ?? ?? dc 11 06 2c 07 11 06 ?? ?? ?? ?? ?? dc 11 05 2c 07 11 05 ?? ?? ?? ?? ?? dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

