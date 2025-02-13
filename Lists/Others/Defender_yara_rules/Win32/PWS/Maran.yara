rule PWS_Win32_Maran_M_2147619199_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Maran.M"
        threat_id = "2147619199"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Maran"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 00 dd 6d 00 6a 00 6a 00 e8 ?? ?? ?? ?? a3 [0-8] 68 ?? ?? ?? ?? 68 10 27 00 00 6a 00 6a 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb 0c}  //weight: 5, accuracy: Low
        $x_1_2 = {76 67 61 64 6f 77 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {76 67 61 64 30 77 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

