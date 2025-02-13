rule Trojan_Win64_Runner_EC_2147850519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runner.EC!MTB"
        threat_id = "2147850519"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f ba f1 1f 49 03 c9 8b 44 11 14 0f ba f0 1f 49 03 c1 8b 34 10 8b 6c 10 04 48 03 f2 74 c8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Runner_MB_2147911089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Runner.MB!MTB"
        threat_id = "2147911089"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Runner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D3Ext/Hooka" ascii //weight: 1
        $x_1_2 = "Shellcode should have been executed!" ascii //weight: 1
        $x_1_3 = "binject" ascii //weight: 1
        $x_1_4 = "SuppaDuppa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

