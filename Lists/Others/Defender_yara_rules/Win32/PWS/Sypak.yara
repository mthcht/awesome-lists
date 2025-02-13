rule PWS_Win32_Sypak_A_2147653765_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Sypak.A"
        threat_id = "2147653765"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Sypak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".GetSkypeAppDataDir" ascii //weight: 1
        $x_1_2 = "Skype\\Apps\\login\\index.html" wide //weight: 1
        $x_1_3 = "Projects\\SFlooder\\" ascii //weight: 1
        $x_2_4 = {50 8b 45 08 50 ff 15 ?? ?? ?? ?? 8b f8 8b c6 8d 50 01 8d 49 00 8a 08 40 84 c9 75 f9 2b c2 50 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c 8b c7}  //weight: 2, accuracy: Low
        $x_2_5 = {50 6a 01 53 6a 26 53 ff 15 ?? ?? ?? ?? 8d bd ?? fe ff ff 4f 8d 9b 00 00 00 00 8a 47 01 47 3a c3 75 f8 b9 05 00 00 00 be ?? ?? ?? ?? f3 a5 68 03 01 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

