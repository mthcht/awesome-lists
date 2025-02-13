rule TrojanDropper_Win32_Runsin_A_2147607440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Runsin.A"
        threat_id = "2147607440"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Runsin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 0e 8b 45 e4 03 c1 80 30 ?? 41 3b 4d ?? 72 f2 8d 45 bc 53 50 ff 75 ?? ff 75 e4 ff 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

