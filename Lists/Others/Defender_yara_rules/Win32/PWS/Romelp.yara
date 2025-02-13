rule PWS_Win32_Romelp_A_2147616684_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Romelp.A"
        threat_id = "2147616684"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Romelp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 1a 8a 93 ?? ?? ?? ?? 30 16 46 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 48 75 e6}  //weight: 2, accuracy: Low
        $x_2_2 = {7e 19 8a 98 ?? ?? ?? ?? 30 19 41 40 25 07 00 00 80 79 05 48 83 c8 f8 40 4a 75 e7}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 45 f0 8a 80 ?? ?? ?? ?? 8b 55 ec 30 02 ff 45 ec ff 45 f0 8b 45 f0 25 07 00 00 80 79 05}  //weight: 2, accuracy: Low
        $x_6_4 = {ba 08 00 00 00 e8 ?? ?? ?? ?? 81 7d ?? f0 d5 ed c5 75 ?? 83 7d ?? 00 74 ?? 83 7d ?? ff 74}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

