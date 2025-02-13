rule Trojan_Win32_FraudLoad_A_2147917886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FraudLoad.A!MTB"
        threat_id = "2147917886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FraudLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 2c eb 03 8b 46 30 99 2b c2 d1 f8 01 43 2c 8b 43 2c 03 c1 c7 45 dc 01 00 00 00 eb 31 8b 55 e8 39 53 30 0f 82 f6 00 00 00 8b 96 bc 00 00 00 3b c2 7e 08 85 d2 0f 8f e4 00 00 00 40 89 43 34 8b 43 2c 03 c1 ff 45 ec c7 43 30 00 00 00 00 8b 55 f4 89 43 28 89 53 14 8b 53 24 89 4b 18 8b 46 18 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

