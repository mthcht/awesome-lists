rule Trojan_Win32_Prepscram_A_2147794359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prepscram.A!MTB"
        threat_id = "2147794359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prepscram"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8c 35 ?? ?? ?? ?? 0f b6 c2 03 c8 81 e1 ff 00 00 00 0f b6 84 0d ?? ?? ?? ?? 8b 4d f8 30 44 0f ff 3b 7d fc}  //weight: 1, accuracy: Low
        $x_1_2 = "CTS.exe" ascii //weight: 1
        $x_1_3 = "3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

