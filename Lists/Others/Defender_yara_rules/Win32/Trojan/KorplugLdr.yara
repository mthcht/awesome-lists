rule Trojan_Win32_KorplugLdr_D_2147974553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KorplugLdr.D!dha"
        threat_id = "2147974553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KorplugLdr"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 45 f4 0a d1 65 f4 83 45 f4 fb 8b 75 f4 eb 08 ff 45 ec eb 03 ff 4d ec 80 ?? 03 ?? eb c5 83 65 f0 00 31 f6 85 f6 74 0b 83 fe 64 74 eb 8b 7d f0 4f eb 03}  //weight: 1, accuracy: Low
        $x_1_2 = {83 45 f8 0a d1 65 f8 83 45 f8 fb 8b 55 f8 eb 08 ff 45 f0 eb 03 ff 4d f0 80 ?? 03 ?? eb c9 83 65 f4 00 31 d2 85 d2 74 0b 83 fa 64 74 eb 8b 75 f4 4e eb 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

