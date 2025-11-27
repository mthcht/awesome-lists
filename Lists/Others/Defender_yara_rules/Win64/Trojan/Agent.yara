rule Trojan_Win64_Agent_NME_2147809855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Agent.NME!MTB"
        threat_id = "2147809855"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b c3 8b ca [0-10] 80 30 20 48 ff c0 48 ff c9 75}  //weight: 1, accuracy: Low
        $x_1_2 = "LockDownProtectProcessById" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Agent_ARR_2147958430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Agent.ARR!MTB"
        threat_id = "2147958430"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Agent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = "main.EIvKAkH.func1.1" ascii //weight: 15
        $x_10_2 = "main.TXpEFfBr.func1.gowrap1" ascii //weight: 10
        $x_5_3 = {48 89 44 24 30 48 8b 59 ?? 48 8b 11 48 c1 e0 ?? 48 8b 0c 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

