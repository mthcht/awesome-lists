rule Trojan_Win64_Micuda_A_2147708477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Micuda.A"
        threat_id = "2147708477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Micuda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "frank095" ascii //weight: 1
        $x_1_2 = "3j2k23" ascii //weight: 1
        $x_1_3 = "DataGen v1.03" ascii //weight: 1
        $x_1_4 = "cpuminer/2.3.3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

