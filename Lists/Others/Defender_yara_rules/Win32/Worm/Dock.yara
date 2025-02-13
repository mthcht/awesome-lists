rule Worm_Win32_Dock_A_2147624386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dock.A"
        threat_id = "2147624386"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {eb 66 8b 5d f8 50 53 e8 88 fe ff ff 85 c0 59 59 be 00 30 00 00 74 13 6a 40}  //weight: 2, accuracy: High
        $x_2_2 = {6a 10 8d 45 ec 50 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 33 c0 81 7d f8 15 2d 01 00}  //weight: 2, accuracy: Low
        $x_2_3 = {8d 48 10 56 c7 45 70 15 2d 01 00 c7 45 68 01 00 00 00 89 45 64 89 4d 6c}  //weight: 2, accuracy: High
        $x_1_4 = "%spagefiles.dat" ascii //weight: 1
        $x_1_5 = "%stemp.tmp" ascii //weight: 1
        $x_1_6 = "%s\\mssetup.exe" ascii //weight: 1
        $x_1_7 = "%s\\ws2help.dll" ascii //weight: 1
        $x_1_8 = "%s\\~$%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

