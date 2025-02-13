rule PWS_Win32_Morbuk_A_2147636405_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Morbuk.A"
        threat_id = "2147636405"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Morbuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 ec 08 89 45 fc 8b 45 fc 25 00 80 00 80 89 45 f8 83 7d f8 00 0f 95 c0 0f b6 c0}  //weight: 2, accuracy: High
        $x_1_2 = {5b 44 4f 57 4e 5d 00 5b 53 4e 41 50 5d}  //weight: 1, accuracy: High
        $x_1_3 = {5b 46 32 32 5d 00 5b 46 32 33 5d}  //weight: 1, accuracy: High
        $x_1_4 = {68 6b 62 2e 64 6c 6c 00 45 6e 64 48 6f 6f 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

