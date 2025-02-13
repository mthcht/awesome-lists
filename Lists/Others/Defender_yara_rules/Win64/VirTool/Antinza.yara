rule VirTool_Win64_Antinza_G_2147851409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Antinza.G!MTB"
        threat_id = "2147851409"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Antinza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Athena.Models.Comms.SMB" ascii //weight: 1
        $x_1_2 = "Athena.Handler.Dynamic" ascii //weight: 1
        $x_1_3 = "Athena.Models.Config" ascii //weight: 1
        $x_1_4 = "Athena.Commands" ascii //weight: 1
        $x_1_5 = "Athena.Models.Mythic.Checkin" ascii //weight: 1
        $x_1_6 = "Athena.Utilities" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Antinza_I_2147903670_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Antinza.I"
        threat_id = "2147903670"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Antinza"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Agent.Profiles.Http" wide //weight: 1
        $x_1_2 = "Agent.deps.json" wide //weight: 1
        $x_1_3 = "Agent.Managers" wide //weight: 1
        $x_1_4 = "Agent.Crypto.Aes" wide //weight: 1
        $x_1_5 = "Agent.Models" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

