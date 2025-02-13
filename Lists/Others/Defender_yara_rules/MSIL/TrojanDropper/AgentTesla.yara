rule TrojanDropper_MSIL_AgentTesla_AB_2147850093_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AgentTesla.AB!MTB"
        threat_id = "2147850093"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 00 00 04 7e 06 00 00 04 7f 08 00 00 04 28 23 00 00 0a 28 24 00 00 0a 6f 25 00 00 0a 28 24 00 00 0a 28 26 00 00 0a 80 07 00 00 04 28 27 00 00 0a 72 17 00 00 70 28 28 00 00 0a 7f 08 00 00 04 28 23 00 00 0a 28 29 00 00 0a 28 24 00 00 0a 18 73 2a 00 00 0a 80 0a 00 00 04 7e 0a 00 00 04 7e 07 00 00 04 16 7e 07 00 00 04 8e b7 6f 2b 00 00 0a 7e 0a 00 00 04 6f 2c 00 00 0a}  //weight: 5, accuracy: High
        $x_5_2 = {72 1b 00 00 70 17 8d 03 00 00 01 0d 09 16 28 27 00 00 0a 72 17 00 00 70 28 28 00 00 0a 7f 08 00 00 04 28 23 00 00 0a 28 29 00 00 0a a2 09}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_AgentTesla_ARA_2147892020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AgentTesla.ARA!MTB"
        threat_id = "2147892020"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your@Split@Here" ascii //weight: 2
        $x_2_2 = "YOUR@PASSWORD@HERE" ascii //weight: 2
        $x_2_3 = "\\file1.exe" ascii //weight: 2
        $x_2_4 = "WindowsApp3.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_AgentTesla_NGT_2147892260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AgentTesla.NGT!MTB"
        threat_id = "2147892260"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 72 d7 00 00 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 0d 11 0d 2c 24 09 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 13 0e 11 0e 17 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsApp1.Resources" ascii //weight: 1
        $x_1_3 = "CypherTeam" ascii //weight: 1
        $x_1_4 = "$666b1ece-7a9e-4b63-a3a1-67d9446f5b00" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_AgentTesla_AAT_2147923704_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/AgentTesla.AAT!MTB"
        threat_id = "2147923704"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 07 02 17 8d 03 00 00 01 13 0a 11 0a 16 11 07 8c 16 00 00 01 a2 11 0a 14 28 ?? 00 00 0a 28 ?? 00 00 0a 09 b4 28 ?? 00 00 06 28 ?? 00 00 0a 9c 11 07 17 d6 13 07 11 07 11 0b 3e 48 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

