rule Trojan_Win64_Miner_GTT_2147930854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Miner.GTT!MTB"
        threat_id = "2147930854"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Miner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 0f af f0 4d 01 f7 4c 89 f8 50 58 48 89 45 ?? 4c 63 7d ?? 48 63 8c 24 ?? 01 00 00 49 29 cf 4c 89 f8 50 58 89 45 ?? 48 c7 c0 80 00 00 00 48 89 c0 50 48 63 45 ?? 50 59 5a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Miner_MX_2147978749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Miner.MX!MTB"
        threat_id = "2147978749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Miner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "api/miners/submit" ascii //weight: 10
        $x_1_2 = "SELECT SerialNumber FROM Win32_BaseBoard" ascii //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_4 = "[+] File marked for deletion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

