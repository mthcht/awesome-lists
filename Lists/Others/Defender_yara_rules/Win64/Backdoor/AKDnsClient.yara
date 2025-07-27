rule Backdoor_Win64_AKDnsClient_A_2147947557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/AKDnsClient.A"
        threat_id = "2147947557"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "AKDnsClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 73 75 6c 74 5f 72 65 63 65 69 76 65 64 ?? 56 48 42 44 40 48 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

