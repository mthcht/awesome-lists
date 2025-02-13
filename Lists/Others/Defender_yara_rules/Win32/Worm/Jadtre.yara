rule Worm_Win32_Jadtre_D_2147633691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Jadtre.gen!D"
        threat_id = "2147633691"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Jadtre"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 45 a8 43 3a 5c 63 c7 45 ac 6d 74 2e 65 c7 45 b0 78 65 00 00 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0}  //weight: 2, accuracy: High
        $x_1_2 = "at \\\\%s %d:%d C:\\%s.exe" ascii //weight: 1
        $x_1_3 = "%s&flag=%s&alexa=0&List=%s" ascii //weight: 1
        $x_1_4 = {62 72 6f 77 73 65 72 [0-4] 5c 5c 25 73 5c 70 69 70 65 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

