rule TrojanSpy_Win32_Wetoxy_A_2147655330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wetoxy.A"
        threat_id = "2147655330"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wetoxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {aa ff 15 60 20 40 00 2e 00 54 c6 44 24 ?? 69 c6 44 24 ?? 74 c6 44 24 ?? 6c c6 44 24 ?? 65 c6 44 24 ?? 3a c6 44 24 ?? 5b c6 44 24 ?? 25 c6 44 24 ?? 73 c6 44 24 ?? 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 37 51 68 ?? ?? ?? ?? c6 44 24 ?? 25 c6 44 24 ?? 73 c6 44 24 ?? 5c c6 44 24 ?? 62}  //weight: 1, accuracy: Low
        $x_1_3 = {2e c6 44 24 ?? 6c c6 44 24 ?? 6f c6 44 24 ?? 67 88 5c 24 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = {55 c6 44 24 ?? 73 c6 44 24 ?? 72 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Wetoxy_B_2147655331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Wetoxy.B"
        threat_id = "2147655331"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Wetoxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 45 dc 5c c6 45 dd 64 c6 45 de 6f c6 45 df 63 c6 45 e0 75 c6 45 e1 6d c6 45 e2 65 c6 45 e3 6e c6 45 e4 74 c6 45 e5 73 c6 45 e6 2e c6 45 e7 6c c6 45 e8 6f c6 45 e9 67 c6 45 ea 00}  //weight: 1, accuracy: High
        $x_1_2 = {fe ff ff 47 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 52 c6 85 ?? fe ff ff 61 c6 85 ?? fe ff ff 77 c6 85 ?? fe ff ff 49 c6 85 ?? fe ff ff 6e c6 85 ?? fe ff ff 70 c6 85 ?? fe ff ff 75 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 44 c6 85 ?? fe ff ff 61 c6 85 ?? fe ff ff 74 c6 85 ?? fe ff ff 61}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 57 69 6e 64 6f 77 73 20 32 30 30 30 2f 58 50 3a 20 58 31 20 6d 6f 75 73 65 20 62 75 74 74 6f 6e 5d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

