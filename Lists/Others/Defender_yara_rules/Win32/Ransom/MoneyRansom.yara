rule Ransom_Win32_MoneyRansom_YAC_2147922135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MoneyRansom.YAC!MTB"
        threat_id = "2147922135"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MoneyRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 f0 89 b5 90 e0 ff ff 8b 85 88 e1 ff ff 30 8d b7 e0 ff ff 0f b6 d0 0f b7 05 70 c6 49 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

