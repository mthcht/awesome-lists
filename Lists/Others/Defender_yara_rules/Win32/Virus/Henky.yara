rule Virus_Win32_Henky_A_2147602538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Henky.gen!A"
        threat_id = "2147602538"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Henky"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {43 4f 44 45 44 [0-8] 42 59 [0-8] 48 65 6e 4b 79}  //weight: 100, accuracy: Low
        $x_100_2 = "VIRUS" ascii //weight: 100
        $x_1_3 = {8b 04 24 66 33 c0 80 38 4d 74 ?? 2d 00 10 00 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

