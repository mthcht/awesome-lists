rule Trojan_Win64_T1057_ProcessDiscovery_A_2147846090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1057_ProcessDiscovery.A"
        threat_id = "2147846090"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1057_ProcessDiscovery"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sekurlsa::minidump" wide //weight: 10
        $x_10_2 = "sekurlsa::bootkey" wide //weight: 10
        $x_10_3 = "sekurlsa::process" wide //weight: 10
        $x_10_4 = "misc::detours" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

