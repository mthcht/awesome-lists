rule Trojan_Win64_T1003_005_CachedDomainCredentials_A_2147846082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1003_005_CachedDomainCredentials.A"
        threat_id = "2147846082"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1003_005_CachedDomainCredentials"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "lsadump::cache" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

