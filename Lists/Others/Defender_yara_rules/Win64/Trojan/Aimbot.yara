rule Trojan_Win64_Aimbot_YAC_2147977328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Aimbot.YAC!MTB"
        threat_id = "2147977328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Aimbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Game Explorer" ascii //weight: 3
        $x_3_2 = "External overlay for Roblox" ascii //weight: 3
        $x_3_3 = "Config successfully loaded" ascii //weight: 3
        $x_3_4 = "Aim Field of View" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

