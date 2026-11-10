rule Trojan_Win32_GreenLagoon_ZZ_2147981804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GreenLagoon.ZZ!sms"
        threat_id = "2147981804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GreenLagoon"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 f9 8b c7 c1 e8 04 c1 e0 04 8b cf 83 e1 0f 0f b6 94 08 ?? ?? ?? ?? 0f b6 c3 8b c8 83 e0 0f c1 e9 04 c1 e1 04 8a 8c 01 ?? ?? ?? ?? 0f b6 44 24 0f 88 54 24 0c 8b d0 83 e0 0f c1 ea 04 c1 e2 04}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 1e 8b cf d3 cb 8d 0c 28 83 c7 06 30 18 8b 1e d3 cb 8d 0c 02 30 58 01 8b 1e d3 cb 8b 4c 24 0c 03 c8 30 58 02 8b 1e d3 cb 8b 4c 24 10 03 c8 30 58 03 8b 1e d3 cb 8b 4c 24 14 03 c8 83 c0 06 30 58 fe 8b 1e d3 cb 30 58 ff 83 ff 10 72}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

