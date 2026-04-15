rule Ransom_Win64_AgentB_AHB_2147967063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/AgentB.AHB!MTB"
        threat_id = "2147967063"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "AgentB"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "YOUR SYSTEM HAS BEEN LOCKED." ascii //weight: 10
        $x_30_2 = "sendToC2({ token: t, type: 'persistent_injection', hostname: require('os').hostname() })" ascii //weight: 30
        $x_20_3 = "ALL YOUR DATA HAS BEEN ENCRYPTED BY DEEPSIDE V2.0" ascii //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

