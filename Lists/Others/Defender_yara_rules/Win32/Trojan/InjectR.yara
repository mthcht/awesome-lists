rule Trojan_Win32_InjectR_2147729957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InjectR!MTB"
        threat_id = "2147729957"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectR"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 46 00 75 00 63 00 6b 00 20 00 59 00 6f 00 75 00 20 00 4e 00 4f 00 44 00 2c 00 20 00 41 00 56 00 41 00 53 00 54 00 20 00 61 00 6e 00 64 00 20 00 61 00 6c 00 6c 00 20 00 41 00 56 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

