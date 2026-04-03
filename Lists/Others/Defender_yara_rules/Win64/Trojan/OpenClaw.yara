rule Trojan_Win64_OpenClaw_GY_2147964927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OpenClaw.GY!MTB"
        threat_id = "2147964927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OpenClaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TradeAI.exe" wide //weight: 1
        $x_1_2 = "Automatic hardware driver update tool" wide //weight: 1
        $x_1_3 = "Real-time AI analysis and predictive modeling toolkit" wide //weight: 1
        $x_1_4 = "TradeAI nofilabs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_OpenClaw_BA_2147966283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/OpenClaw.BA!MTB"
        threat_id = "2147966283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "OpenClaw"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Trade AI Labs" ascii //weight: 1
        $x_1_2 = "TradeAI.exe" ascii //weight: 1
        $x_1_3 = "AI analysis and predictive modeling toolkit." ascii //weight: 1
        $x_1_4 = "Automatic hardware driver update tool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

