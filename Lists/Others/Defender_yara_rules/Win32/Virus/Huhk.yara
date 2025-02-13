rule Virus_Win32_Huhk_A_2147608951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Huhk.gen!A"
        threat_id = "2147608951"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Huhk"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 12 8a 06 0a c0 74 06 38 d8 74 02 32 c3 88 07 47 46 e2 ee 8b c2 83 c2 08 83 3a 00 75 d7 5b 58 8d 88 ?? ?? 00 00 ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

