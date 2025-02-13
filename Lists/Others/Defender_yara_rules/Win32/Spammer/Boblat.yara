rule Spammer_Win32_Boblat_A_2147685068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Boblat.A"
        threat_id = "2147685068"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Boblat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 0e 00 07 80 74 ?? 3d 08 00 0c 80 74 ?? 3b c7 75 ?? 33 c0 40 a3}  //weight: 10, accuracy: Low
        $x_5_2 = {50 68 13 00 00 20 57}  //weight: 5, accuracy: High
        $x_1_3 = {0f b6 86 99 01 00 00 50 0f b6 86 98 01 00 00 50 0f b6 86 97 01 00 00 50 0f b6 86 96 01 00 00 50 0f b6 86 95 01 00 00 50 0f b6 86 94 01 00 00 50}  //weight: 1, accuracy: High
        $x_1_4 = "--=_BlatBoundary-" ascii //weight: 1
        $x_1_5 = "http://%s%s%s" ascii //weight: 1
        $x_1_6 = "/smtp/smtp.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

