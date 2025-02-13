rule Worm_Win32_Bundiso_A_2147707787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Bundiso.A"
        threat_id = "2147707787"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Bundiso"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {34 6d 75 10 c7 45 fc ?? 00 00 00 8b ?? 08 66 c7 ?? 34 63 00 c7 45 f0 00 00 00 00 68 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\movies.exe" wide //weight: 1
        $x_1_3 = ":\\autorun.inf" wide //weight: 1
        $x_1_4 = "\\Sanchitha\\Desktop\\virus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

