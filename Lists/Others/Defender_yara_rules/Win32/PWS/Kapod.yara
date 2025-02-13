rule PWS_Win32_Kapod_B_2147627429_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kapod.B"
        threat_id = "2147627429"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kapod"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 50 65 72 66 6c 69 62 5c 25 33 2e 33 78 00 00 2e 73 72 66 00 00 00 00 2e 73 72 66 00 00 00 00 2e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_2 = "regsid.php?windows_name=" ascii //weight: 10
        $x_5_3 = {2e 6e 65 2e 6a 70 2f [0-16] 2e 70 68 70}  //weight: 5, accuracy: Low
        $x_5_4 = "_stop.exe.txt" ascii //weight: 5
        $x_1_5 = "&email_name=" ascii //weight: 1
        $x_1_6 = "&url_a=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

