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

