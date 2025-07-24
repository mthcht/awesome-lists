rule Trojan_Win64_BrowserStealer_RDA_2147842954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrowserStealer.RDA!MTB"
        threat_id = "2147842954"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 e1 07 0f b6 4c 0d b7 32 0c 02 48 8d 45 d7 49 83 ff 10 49 0f 43 c6 88 0c 02 41 ff c0 48 ff c2 49 63 c8 4c 8b 7d ef 4c 8b 75 d7 48 3b 4b 10}  //weight: 2, accuracy: High
        $x_1_2 = "\\Mozilla\\Firefox\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BrowserStealer_GVA_2147947384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrowserStealer.GVA!MTB"
        threat_id = "2147947384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 d3 ea 41 8b c8 48 d3 e0 40 0f b6 cf 48 8b 7c 24 40 0a d0 41 0f b6 c2 d2 e0 41 0f b6 c9 41 d2 ea 41 0a c2 32 d0 0f b6 c2}  //weight: 3, accuracy: High
        $x_1_2 = "chrome" wide //weight: 1
        $x_1_3 = "firefox" wide //weight: 1
        $x_1_4 = "opera" wide //weight: 1
        $x_1_5 = "brave" wide //weight: 1
        $x_3_6 = "taskkill /IM " wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

