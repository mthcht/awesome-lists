rule Trojan_Win64_JumboKiller_A_2147977556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/JumboKiller.A"
        threat_id = "2147977556"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "JumboKiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 00 21 00 5d 00 20 00 46 00 4f 00 55 00 4e 00 44 00 3a 00 20 00 25 00 6c 00 73 00 20 00 28 00 50 00 49 00 44 00 3a 00 20 00 25 00 6c 00 75 00 29 00 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 00 2b 00 5d 00 20 00 46 00 49 00 58 00 45 00 44 00 3a 00 20 00 25 00 6c 00 73 00 20 00 28 00 50 00 49 00 44 00 3a 00 20 00 25 00 6c 00 75 00 29 00 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 00 2d 00 5d 00 20 00 46 00 41 00 49 00 4c 00 45 00 44 00 3a 00 20 00 25 00 6c 00 73 00 20 00 28 00 45 00 72 00 72 00 6f 00 72 00 3a 00 20 00 25 00 6c 00 75 00 29 00 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {5b 00 2a 00 5d 00 20 00 43 00 68 00 65 00 63 00 6b 00 65 00 64 00 20 00 25 00 64 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 73 00 2c 00 20 00 74 00 65 00 72 00 6d 00 69 00 6e 00 61 00 74 00 65 00 64 00 20 00 25 00 64 00 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = "SentinelStaticEngineScanner.exe" wide //weight: 1
        $x_1_6 = "Sophos.PolicyEvaluation.Service.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

