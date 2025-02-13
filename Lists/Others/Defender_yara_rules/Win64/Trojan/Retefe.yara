rule Trojan_Win64_Retefe_A_2147727653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Retefe.A"
        threat_id = "2147727653"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Retefe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 3a 5c 4a 4f 42 5c 70 72 6f 6a 65 63 74 73 5c 43 2b 2b 5c 4a 53 4c 6f 61 64 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4a 53 4c 6f 61 64 65 72 2e 70 64 62 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

