rule Trojan_Win64_Tinukebot_GA_2147924837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tinukebot.GA!MTB"
        threat_id = "2147924837"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tinukebot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "string too long" ascii //weight: 1
        $x_3_2 = "176.111.174.140" ascii //weight: 3
        $x_1_3 = "/api.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Tinukebot_AMDG_2147932736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tinukebot.AMDG!MTB"
        threat_id = "2147932736"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tinukebot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://176.113.115.149" wide //weight: 10
        $x_10_2 = "http://185.81.68.156" wide //weight: 10
        $x_1_3 = "url_blacklist" ascii //weight: 1
        $x_1_4 = "AVGBrowser.exe" ascii //weight: 1
        $x_1_5 = "injects" ascii //weight: 1
        $x_1_6 = "Credit Card Number" ascii //weight: 1
        $x_1_7 = "ReflectiveLoader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

