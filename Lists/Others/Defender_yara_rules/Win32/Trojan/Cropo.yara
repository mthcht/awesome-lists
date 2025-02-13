rule Trojan_Win32_Cropo_A_2147597896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cropo.gen!A"
        threat_id = "2147597896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cropo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 1c 0f b7 45 fe 48 48 0f 84 ab 00 00 00 83 e8 03 0f 84 99 00 00 00 2b c6 74 56 48 74 0c 8b 07 8b cf ff 50 3c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f8 8b 88 ?? ?? 40 00 8b 45 0c 6a ff e8 ?? ?? 00 00 85 c0 59 74 5f 8b 55 08 56 8d bd e4 fb ff ff e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

