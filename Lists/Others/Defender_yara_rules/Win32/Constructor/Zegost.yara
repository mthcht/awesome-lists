rule Constructor_Win32_Zegost_A_2147705830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Constructor:Win32/Zegost.A"
        threat_id = "2147705830"
        type = "Constructor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 68 30 73 74 20 52 41 54 20 45 78 63 65 70 74 69 6f 6e 00 43 52 41 53 48 20 43 4f 44 45 3a 30 78 25 2e 38 78 20 41 44 44 52 3d 30 78 25 2e 38 78 20 46 4c 41 47 53 3d 30 78 25 2e 38 78}  //weight: 1, accuracy: High
        $x_1_2 = {43 47 68 30 73 74 44 6f 63 00}  //weight: 1, accuracy: High
        $x_1_3 = "del /q /s /a c:\\URatCache" ascii //weight: 1
        $x_1_4 = "\\Update\\Server.Dat" ascii //weight: 1
        $x_1_5 = {43 4d 6f 72 65 44 64 6f 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

