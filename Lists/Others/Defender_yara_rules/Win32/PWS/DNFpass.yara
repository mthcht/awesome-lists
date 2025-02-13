rule PWS_Win32_DNFpass_A_2147641420_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/DNFpass.A"
        threat_id = "2147641420"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "DNFpass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 11 27 00 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00}  //weight: 1, accuracy: Low
        $x_2_2 = {68 b2 27 00 00 ?? 68 01 02 00 00 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_1_3 = {c1 e0 10 03 45 ?? 6a 1c}  //weight: 1, accuracy: Low
        $x_2_4 = {33 f6 56 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00 6a 03 56 56 56 56 6a 01 ff 35 ?? ?? 40 00 ff 15 ?? ?? 40 00}  //weight: 2, accuracy: Low
        $x_1_5 = {54 57 49 4e 43 4f 4e 54 52 4f 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

