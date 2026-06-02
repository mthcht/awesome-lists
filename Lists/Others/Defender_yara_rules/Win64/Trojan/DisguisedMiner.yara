rule Trojan_Win64_DisguisedMiner_AMX_2147964761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DisguisedMiner.AMX!MTB"
        threat_id = "2147964761"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DisguisedMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b 4b 38 48 85 c9 74 49 48 8b 01 ff 50 10 84 c0 75 24 48 83 c3 40 48 3b df 75 e4 48 8b 4e 40 48 8b 41 18 48 8b 50 28 80 7a 23 00}  //weight: 10, accuracy: High
        $x_1_2 = "Services and Controller app" wide //weight: 1
        $x_1_3 = "java.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_DisguisedMiner_GMX_2147970683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DisguisedMiner.GMX!MTB"
        threat_id = "2147970683"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DisguisedMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 48 ff c7 08 c0 74 d7 79 0a 48 0f b7 17 48 83 c7 02 eb 0a 48 89 f9 48 89 fa ff c8 f2 ae 48 89 e9 ff 15 ?? ?? ?? ?? 48 09 c0 74 09 48 89 03 48 83 c3 08}  //weight: 1, accuracy: Low
        $x_1_2 = "method\":\"keepalived" ascii //weight: 1
        $x_1_3 = "your IP is banned" ascii //weight: 1
        $n_100_4 = "Usage:" ascii //weight: -100
        $n_100_5 = "[OPTIONS]" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

