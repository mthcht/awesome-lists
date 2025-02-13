rule Trojan_Win64_GaryStealer_A_2147892619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GaryStealer.A!MTB"
        threat_id = "2147892619"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GaryStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ShellCode33/VM-Detection" ascii //weight: 2
        $x_2_2 = "gary-macos-stealer-malware/agent/win" ascii //weight: 2
        $x_2_3 = "server finished" ascii //weight: 2
        $x_2_4 = "extended master secret" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

