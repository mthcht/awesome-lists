rule Worm_Win32_Liajred_2147605119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Liajred"
        threat_id = "2147605119"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Liajred"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 53 53 53 53 53 6a ff 51 e8}  //weight: 1, accuracy: High
        $x_1_2 = "x-fly in da house" wide //weight: 1
        $x_1_3 = "MSFLC.FYS" wide //weight: 1
        $x_1_4 = "NTLS.DYS" wide //weight: 1
        $x_1_5 = "C:\\soulfly" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

