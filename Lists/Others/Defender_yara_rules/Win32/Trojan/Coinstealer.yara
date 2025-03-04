rule Trojan_Win32_Coinstealer_BO_2147827261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Coinstealer.BO!MTB"
        threat_id = "2147827261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Coinstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 19 30 03 43 83 ea 01 75 f5 8b 7d f8 8d 75 e4 83 e9 10 83 6d fc 01 89 4d 08 8b 4d f4}  //weight: 1, accuracy: High
        $x_1_2 = {8a 42 f3 32 c4 88 42 03 8a 42 f4 32 45 fd 88 42 04 8a 42 f5 32 c1 88 42 05 8a 42 f6 32 c5 43 88 42 06 83 c2 04 83 fb 2c 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

