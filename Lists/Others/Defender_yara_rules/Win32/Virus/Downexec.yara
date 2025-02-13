rule Virus_Win32_Downexec_A_2147627684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Downexec.gen!A"
        threat_id = "2147627684"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Downexec"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 00 00 ff ff 81 38 4d 5a 90 00 74 07 2d 00 10 00 00 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 3f 47 65 74 50 75 ?? 8b df 83 c3 04 81 3b 72 6f 63 41}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c0 01 81 38 8b ff 55 8b 74 05 83 c0 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

