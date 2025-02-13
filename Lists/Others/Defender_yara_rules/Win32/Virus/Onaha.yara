rule Virus_Win32_Onaha_B_2147724671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Onaha.B!bit"
        threat_id = "2147724671"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Onaha"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\Hana8O.exe" ascii //weight: 2
        $x_1_2 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_4 = {81 e2 01 00 00 80 79 05 4a 83 ca fe 42 8a ?? ?? 08 75 05 80 f1 55 eb 03 80 f1 aa 88 ?? ?? 08 40 3d fe 01 00 00 7c d7}  //weight: 2, accuracy: Low
        $x_1_5 = {6a 00 6a 00 6a 00 6a 04 55 ff 15 ?? ?? 40 00 8b f0 85 f6 0f 84 92 00 00 00 66 8b 06 66 3d 4d 5a 74 06 66 3d 5a 4d 75 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

