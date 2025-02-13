rule Virus_Win32_Pavsee_A_2147624052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Pavsee.gen!A"
        threat_id = "2147624052"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Pavsee"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 62 00 00 72 62 00 00 72 62 2b 00 41 63 63 65 70 74 3a 20 2a 2f 2a 0d 0a 0d 0a 00 48 6f 73 74 3a 20 00 00 0d 0a 00 00 2e 74 78 74 20 48 54 54 50 2f 31 2e 31 0d 0a 00 47 45 54 20 2f 00 00 00 2e 65 78 65 00 00 00 00 2e 74 6d 70 00 00 00 00 5c 00 00 00 2e 6c 6e 6b 00 00 00 00 3a 5c 00 00 2e 63 6f 6d 00 00 00 00 2a 2e 2a 00 54 45 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff 66 c7 85 ?? ?? ff ff ?? ?? 66 c7 85 ?? ?? ff ff ?? ?? 66 89 b5 ?? ?? ff ff 8d bd fc ?? ?? ff f3 ab 59 66 c7 85 ?? ?? ff ff 77 00 66 c7 85 ?? ?? ff ff 77 00 66 c7 85 ?? ?? ff ff 77 00 66 89 95 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

