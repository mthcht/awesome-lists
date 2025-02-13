rule Backdoor_Win32_Ysnah_DD_2147725995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Ysnah.DD"
        threat_id = "2147725995"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Ysnah"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mozilla/4.0 (compatible; MSIE 8.0; Win32)" ascii //weight: 1
        $x_2_2 = "3765-4591-E8DF-99EJ" ascii //weight: 2
        $x_1_3 = {8d 04 31 8a 1c 07 2a d9 80 eb 0a 41 3b ca 88 18}  //weight: 1, accuracy: High
        $x_1_4 = {88 5d dd c6 45 ?? 30 c6 45 ?? 2e c6 45 ?? 30 c6 45 ?? 2e c6 45 ?? 30 c6 45 ?? 2e c6 45 ?? 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

