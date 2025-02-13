rule Trojan_MSIL_Agent_J_2147652067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.J"
        threat_id = "2147652067"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 5f 00 00 0a 13 09 20 e8 03 00 00 13 0a 11 0a 8d 07 00 00 01 13 0c 11 08 11 0c 16 11 0a 6f 21 00 00 0a 25 26 13 0b 11 0b 16}  //weight: 2, accuracy: High
        $x_2_2 = {28 3f 00 00 0a 25 26 28 40 00 00 0a 25 26 7d 0a 00 00 04 02 11 04 1f 14 9a 7d 0b 00 00 04 02}  //weight: 2, accuracy: High
        $x_1_3 = "msnmsgr.exe" ascii //weight: 1
        $x_1_4 = "get_IsAttached" ascii //weight: 1
        $x_1_5 = "op_Inequality" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Agent_J_2147742406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.J!ibt"
        threat_id = "2147742406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 20 ff 00 00 00 5f 07 25 17 58 0b 61 d2 0d}  //weight: 1, accuracy: High
        $x_1_2 = {25 1e 63 07 25 17 58 0b 61 d2 13 04 26}  //weight: 1, accuracy: High
        $x_1_3 = {11 04 1e 62 09 60 d1 9d}  //weight: 1, accuracy: High
        $x_1_4 = {03 00 0a 6f ?? 02 00 0a}  //weight: 1, accuracy: Low
        $x_1_5 = {00 70 fe 0c 00 00 28 01 00 00 06 28 ?? ?? 00 0a 28 ?? 01 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_6 = "LookupPrivilegeValue" ascii //weight: 1
        $x_1_7 = "AdjustTokenPrivileges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_AI_2147742408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.AI!!ibt"
        threat_id = "2147742408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "log file.exe" ascii //weight: 1
        $x_1_2 = "news.net-freaks.com/upex/Wor" wide //weight: 1
        $x_1_3 = "vboxmrxnp.dll" wide //weight: 1
        $x_1_4 = "vmGuestLib.dll" wide //weight: 1
        $x_1_5 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_6 = "{0}\\root\\SecurityCenter2" wide //weight: 1
        $x_1_7 = "$5f27e92a-6118-4bc7-ac94-354b27f1e80f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_MRS_2147745468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.MRS!MTB"
        threat_id = "2147745468"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 9a 0b 06 07 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 11 04 17 13 06 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 40 ?? ?? ?? ?? 20 ?? ?? ?? ?? 13 06 20 ?? ?? ?? ?? 58 00 58 13 04 11 04 09 8e 69 32 b8 02 03 06 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0c 08 14 04 6f ?? ?? ?? ?? 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {2d 11 14 fe ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 7e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_ICY_2147786567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.ICY!MTB"
        threat_id = "2147786567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 1f 10 8d 44 00 00 01 0a 03 28 20 00 00 0a 0b 28 21 00 00 0a 0c 00 08 28 22 00 00 0a 02 6f 23 00 00 0a 6f 24 00 00 0a 00 08 06 6f 25 00 00 0a 00 08 08 6f 26 00 00 0a 08 6f 27 00 00 0a 6f 28 00 00 0a 0d 07 73 29 00 00 0a 13 04 00 11 04 09 16 73 2a 00 00 0a 13 05 00 11 05 73 2b 00 00 0a 13 06 00 11 06 6f 2c 00 00 0a 13 07 de 32 11 06 2c 08 11 06 6f 2d 00 00 0a 00 dc}  //weight: 1, accuracy: High
        $x_1_2 = "d0179c6da52209982c4383e0" ascii //weight: 1
        $x_1_3 = "Sylvan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_ICY_2147786567_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.ICY!MTB"
        threat_id = "2147786567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 01 0b 00 06 19 17 73 ?? 00 00 0a 0c 00 08 6f ?? 00 00 0a 69 0d 09 8d ?? 00 00 01 0b 16 13 05 2b 07 11 05 11 04 58 13 05 08 07 11 05 09 11 05 59 6f ?? 00 00 0a 25 13 04 16 fe 02 13 06 11 06 2d e0 00 de 0a 00 08 6f ?? 00 00 0a 00 00 dc 00 de 05 26 00 00 de 00 07 13 07 2b 00 11 07 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "DNB_client.exe" ascii //weight: 1
        $x_1_3 = "igx64.exe" ascii //weight: 1
        $x_1_4 = "kookol" ascii //weight: 1
        $x_1_5 = "scont" ascii //weight: 1
        $x_1_6 = "crpt 2.0\\crpt 2.0\\bin\\Debug\\LT\\liprus_prod\\obj\\Debug" ascii //weight: 1
        $x_1_7 = "Download successful" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_UKY_2147787104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.UKY!MTB"
        threat_id = "2147787104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sadlife" ascii //weight: 1
        $x_1_2 = "Digitallify" ascii //weight: 1
        $x_1_3 = "ZhXl39BlhP84+Y4kurA8wpehxxqA0X22IMYZ6Vpiqs" ascii //weight: 1
        $x_1_4 = "whysosad" ascii //weight: 1
        $x_1_5 = "dav.bat" ascii //weight: 1
        $x_1_6 = "DisableTaskMgr" ascii //weight: 1
        $x_1_7 = "DisableAntiSpyware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_UPO_2147794860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.UPO!MTB"
        threat_id = "2147794860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Browser service" ascii //weight: 1
        $x_1_2 = "http://176.111.174.107/Api/GetTask/" ascii //weight: 1
        $x_1_3 = "http://176.111.174.107/chrome.zip" ascii //weight: 1
        $x_1_4 = "UGFIOEHFGIEFIUKUF.Properties.Resources" ascii //weight: 1
        $x_1_5 = "ClientHost.exe" ascii //weight: 1
        $x_1_6 = "weoufgoweifhiuwef" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_DAQ_2147798711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.DAQ!MTB"
        threat_id = "2147798711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stub.exe" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "$5a542c1b-2d36-4c31-b039-26a88d3967da" ascii //weight: 1
        $x_1_4 = "Debugger Detected" ascii //weight: 1
        $x_1_5 = "Stub.pdb" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "get_MachineName" ascii //weight: 1
        $x_1_8 = "njLogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Agent_SPQZ_2147840561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Agent.SPQZ!MTB"
        threat_id = "2147840561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 01 00 00 70 72 17 00 00 70 28 14 00 00 0a 26 20 d0 07 00 00 28 22 00 00 0a 00 72 01 00 00 70 72 b8 00 00 70 28 14 00 00 0a 26 20 b8 0b 00 00 28 22 00 00 0a 00 72 01 00 00 70 72 65 02 00 70 28 14 00 00 0a 26 2a}  //weight: 2, accuracy: High
        $x_1_2 = "ndirmeDenemeleri.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

