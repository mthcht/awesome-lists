rule Trojan_Win64_RemusStealer_ARM_2147969220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RemusStealer.ARM!MTB"
        threat_id = "2147969220"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RemusStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 04 24 48 89 4c 24 08 48 c7 44 24 10 00 00 00 00 48 c7 44 24 18 00 08 00 00 e8 ?? ?? ?? ?? 45 0f 57 ff 4c 8b 35 16 92 2e 00 65 4d 8b 36 4d 8b 36 48 8b 44 24 20 48 85 c0 0f 84 6e 01 00 00 48 89 44 24 28 48 8d 1d 10 25 14 00 b9 1d 00 00 00 48 89 cf e8}  //weight: 2, accuracy: Low
        $x_1_2 = {65 4d 8b 36 4d 8b 36 48 8b 44 24 20 0f 1f 40 00 48 85 c0 0f 84 05 02 00 00 48 8d 1d 4a ee 13 00 b9 0c 00 00 00 48 89 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

