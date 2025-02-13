rule Trojan_Win32_Pabueri_A_2147659627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pabueri.A"
        threat_id = "2147659627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pabueri"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 8b 4d e0 03 4d ?? 88 01 8b 55 e0 03 55 ?? 0f b6 02 8b 4d ?? 0f be 54 0d c0 ?? ?? ?? ?? 33 c2 8b 4d e0 03 4d ?? 88 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {5e 10 69 4c e4 41 60 d5 72 71 67 a2 d1 e4 03 3c 47 d4 04 4b fd 85 0d d2 6b b5 0a a5 fa a8 b5 35 6c 98 b2 42 d6 c9 bb db 40 f9 bc ac e3 6c d8 32}  //weight: 1, accuracy: High
        $x_1_3 = "Start::WindowsFirewallAddApp()" ascii //weight: 1
        $x_1_4 = "Hjbotid:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

