rule Trojan_Win32_Siapag_A_2147616858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Siapag.gen!A"
        threat_id = "2147616858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Siapag"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 04 b9 ?? ?? f9 ?? 8a 02 84 c0 74 0d 34 c5 88 01 8a 42 01 41 42 84 c0 75 f3 c6 01 00 b8 ?? ?? f9 ?? c3}  //weight: 10, accuracy: Low
        $x_1_2 = "cjwewklwreo" ascii //weight: 1
        $x_1_3 = "IsGamePlayer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

