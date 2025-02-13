rule Trojan_Win32_Grazie_A_2147655701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grazie.A"
        threat_id = "2147655701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grazie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" ascii //weight: 1
        $x_1_2 = "DefWatch.exe" ascii //weight: 1
        $x_1_3 = "C:\\TEMP\\AdobeARM.exe" ascii //weight: 1
        $x_1_4 = "Windows+NT+5.1" ascii //weight: 1
        $x_1_5 = {88 5c 24 24 88 5c 24 6c c6 44 24 30 7a c6 44 24 31 54 c6 44 24 32 58 c6 44 24 33 74 88 5c 24 34 c6 44 24 40 89 c6 44 24 41 50 88 4c 24 42 c6 44 24 43 47 c6 44 24 44 0d 88 44 24 45 c6 44 24 46 1a 88 44 24 47 88 5c 24 48 c6 44 24 38 49 c6 44 24 39 45 88 4c 24 3a c6 44 24 3b 44 88 5c 24 3c 89 5c 24 60 89 5c 24 5c 89 9c 24 80 00 00 00 89 5c 24 68 ff 96 98 06 00 00}  //weight: 1, accuracy: High
        $x_2_6 = {8a 44 31 ff 8a 14 31 32 c2 8a d0 c0 ea ?? c0 e0 ?? 0a d0 88 14 31 49 75 ?? 8a 06 8a 4c 24 ?? 32 c1 8a c8 c0 e9 ?? c0 e0 ?? 0a c8 88 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

