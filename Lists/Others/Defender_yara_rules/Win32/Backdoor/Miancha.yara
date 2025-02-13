rule Backdoor_Win32_Miancha_A_2147685193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Miancha.A"
        threat_id = "2147685193"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Miancha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {78 c6 44 24 ?? 7d c6 44 24 ?? 72 c6 44 24 ?? 67 c6 44 24 ?? 3a c6 44 24 ?? 7b c6 44 24 ?? 77 c6 44 24 ?? 6c c6 44 24 ?? 14 [0-5] c6 44 24 ?? 65 [0-3] 80 30 14 75}  //weight: 1, accuracy: Low
        $x_1_2 = "temp\\instructions.pdf" ascii //weight: 1
        $x_1_3 = {43 6f 6e 31 00 00 00 00 43 6f 6e 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

