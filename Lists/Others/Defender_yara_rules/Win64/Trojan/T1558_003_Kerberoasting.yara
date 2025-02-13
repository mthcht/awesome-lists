rule Trojan_Win64_T1558_003_Kerberoasting_A_2147846081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/T1558_003_Kerberoasting.A"
        threat_id = "2147846081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "T1558_003_Kerberoasting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kerberos::ask" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

