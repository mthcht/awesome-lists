rule Trojan_Win64_T1134_005_SidHistoryInjection_A_2147846087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1134_005_SidHistoryInjection.A"
        threat_id = "2147846087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1134_005_SidHistoryInjection"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "sid::add" wide //weight: 10
        $x_10_2 = "kerberos::golden" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

