rule Trojan_Win64_CryptCaller_A_2147962505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CryptCaller.A"
        threat_id = "2147962505"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CryptCaller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d8 ec b0 64 28 fc c0 74}  //weight: 10, accuracy: High
        $x_10_2 = {38 cc 90 44 08 dc a0 54}  //weight: 10, accuracy: High
        $x_1_3 = "ChainingModeCBC" wide //weight: 1
        $x_1_4 = "Unknown pseudo relocation protocol version" ascii //weight: 1
        $x_1_5 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_6 = "BCryptGenerateSymmetricKey" ascii //weight: 1
        $x_1_7 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

