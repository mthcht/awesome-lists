rule Virus_Win32_Tvido_2147598372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Tvido"
        threat_id = "2147598372"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Tvido"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f4 80 38 4d 0f 85 ?? 04 00 00 80 78 01 5a 0f 85 ?? 04 00 00 81 78 22 57 65 65 44 0f 84 ?? 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Tvido_B_2147598892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Tvido.gen!B"
        threat_id = "2147598892"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Tvido"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7e fc 2e 75 ?? 80 7e fd 65 74 06 80 7e fd 45 75 ?? 80 7e fe 78 74 06 80 7e fe 58 75 ?? 80 7e ff 65 74 06 80 7e ff 45 75 ?? 57 ae 75 fd c6 47 ff 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

