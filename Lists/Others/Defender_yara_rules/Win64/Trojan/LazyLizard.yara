rule Trojan_Win64_LazyLizard_A_2147967948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LazyLizard.A"
        threat_id = "2147967948"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LazyLizard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 00 72 00 72 00 6f 00 72 00 3a 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 67 00 65 00 74 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 20 00 66 00 69 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 2e 00 20 00 43 00 6f 00 64 00 65 00 3a 00 20 00 25 00 6c 00 75 00 0a 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 3f 00 3f 00 5c 00 44 00 44 00 43 00 48 00 45 00 4c 00 50 00 45 00 52 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LazyLizard_B_2147967949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LazyLizard.B"
        threat_id = "2147967949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LazyLizard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "All operations were successful" ascii //weight: 1
        $x_1_2 = "sentinelstaticenginescanner.exe" ascii //weight: 1
        $x_1_3 = "SentinelRemediation.exe" ascii //weight: 1
        $x_1_4 = "OWNeacSafe64.sys" ascii //weight: 1
        $x_1_5 = "C:\\Program Files\\SentinelOne" ascii //weight: 1
        $x_1_6 = "CSFalconContainer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

