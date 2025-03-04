rule Trojan_Win64_XmrigMiner_RP_2147911347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/XmrigMiner.RP!MTB"
        threat_id = "2147911347"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "XmrigMiner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "stratum+tcp://" ascii //weight: 1
        $x_1_2 = "stratum+ssl://" ascii //weight: 1
        $x_1_3 = "donate.v2.xmrig.com" ascii //weight: 1
        $x_1_4 = "HWLOC_CPUID_PATH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

