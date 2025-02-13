rule Trojan_Win64_RustyAgent_SK_2147892452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RustyAgent.SK!MTB"
        threat_id = "2147892452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RustyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\",\"tc\":\"TC\",\"nr\":" ascii //weight: 1
        $x_1_2 = "WindowsCurrentVersionRun00rst" ascii //weight: 1
        $x_1_3 = "rust_panic" ascii //weight: 1
        $x_1_4 = "rstMYPATH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

