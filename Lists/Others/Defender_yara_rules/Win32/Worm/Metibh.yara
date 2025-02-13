rule Worm_Win32_Metibh_A_2147610398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Metibh.A"
        threat_id = "2147610398"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Metibh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {50 6a 00 6a 2a ff 15 ?? ?? ?? 01 8b f0 85 f6 0f 84 ?? ?? 00 00 8b ac 24 ?? ?? 00 00 55 ff 15 ?? ?? ?? 01 8b f8 6a 04 47 68 00 10 00 00 57 6a 00 56 ff 15 ?? ?? ?? 01 8b d8 85 db 75}  //weight: 3, accuracy: Low
        $x_3_2 = {b3 63 8d 4c 24 04 88 5c 24 04 51 e8 ?? ?? ?? ff 83 c4 04 fe c3 80 fb 7a 7e e8 5b}  //weight: 3, accuracy: Low
        $x_1_3 = {77 6f 6f 6f 6c 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 61 74 63 68 65 72 00 53 79 73 69 6e 74 65 72 6e 61 6c 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "shellexecute=RunDll32.exe .\\Thumbs.lnk,GetPic" ascii //weight: 1
        $x_1_6 = {47 65 74 50 69 63 00 49 6e 69 74 4e 65 74 00 4e 76 53 74 61 72 74 75 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

