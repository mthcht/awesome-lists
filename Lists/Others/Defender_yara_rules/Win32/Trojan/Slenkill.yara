rule Trojan_Win32_Slenkill_A_179385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Slenkill.gen!A"
        threat_id = "179385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Slenkill"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d f8 08 7d 39 8b 4d 08 03 4d f8 0f be 91 ?? ?? ?? ?? 33 55 fc 8b 45 f4 03 45 f8 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 81 e2 ff 00 00 80 79 08}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 64 ff 15 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? 8d 4d ?? e8 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 eb 09 8b 4d ?? 83 c1 01 89 4d ?? 83 7d ?? 18 7d 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

