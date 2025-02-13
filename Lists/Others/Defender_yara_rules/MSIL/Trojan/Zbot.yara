rule Trojan_MSIL_Zbot_ET_2147797385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zbot.ET!MTB"
        threat_id = "2147797385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 14 0b 14 0c 0e 04 2c 15 06 03 72 76 28 00 70 04 28 12 00 00 0a 6f 13 00 00 0a 0c 2b 1a 06 03 72 76 28 00 70 04 28 12 00 00 0a 6f 14 00 00 0a 0b 07 6f 15 00 00 0a 0c 08 05 6f 16 00 00 0a 07 0e 05 6f 17 00 00 0a 2a}  //weight: 10, accuracy: High
        $x_3_2 = "function1" ascii //weight: 3
        $x_3_3 = "BuildAssembly" ascii //weight: 3
        $x_3_4 = "shellcode" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zbot_CC_2147811075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zbot.CC!MTB"
        threat_id = "2147811075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\VimeWorld.exe" ascii //weight: 1
        $x_1_2 = "https://vk.com/enthhacks" ascii //weight: 1
        $x_1_3 = "https://discord.gg/FEr7dz9hgs" ascii //weight: 1
        $x_1_4 = "enthh.000webhostapp.com" ascii //weight: 1
        $x_1_5 = "log.txt" ascii //weight: 1
        $x_1_6 = "base64_decode" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "Cheat" ascii //weight: 1
        $x_1_9 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_10 = "InjectCheat_Load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zbot_B_2147824014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zbot.B!MTB"
        threat_id = "2147824014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thiago.rclaro\\Dropbox\\Projetos\\BodeOfWar\\BodeOfWarClient\\BodeOfWarClient\\obj\\x86\\Debug\\CantStopClient.pdb" ascii //weight: 1
        $x_1_2 = "CartagenaClient" ascii //weight: 1
        $x_1_3 = "$06a286a8-630a-4d37-86eb-c7da22220667" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zbot_AAAE_2147899477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zbot.AAAE!MTB"
        threat_id = "2147899477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 73 ?? 00 00 0a 13 05 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 02 16 02 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 73 ?? 00 00 0a 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zbot_KAA_2147901602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zbot.KAA!MTB"
        threat_id = "2147901602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {58 0a 06 20 ?? ?? 00 00 58 0a 04 1f 19 64 04 1d 62 60 10 02 06 20 ?? ?? 00 00 58 0a 06 20 ?? ?? 00 00 58 0a 04 03 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

