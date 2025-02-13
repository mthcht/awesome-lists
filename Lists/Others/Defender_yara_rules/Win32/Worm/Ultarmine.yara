rule Worm_Win32_Ultarmine_A_2147689496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ultarmine.A"
        threat_id = "2147689496"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ultarmine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "111.118.183.210" wide //weight: 1
        $x_1_2 = "USBDriver.exe" wide //weight: 1
        $x_1_3 = "1NtK9ryAEV2b9HFMgunQC6qg4BcgVtaC16" wide //weight: 1
        $x_1_4 = {75 00 73 00 65 00 61 00 75 00 74 00 6f 00 70 00 6c 00 61 00 79 00 3d 00 31 00 ?? ?? ?? ?? ?? ?? 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 6f 00 70 00 65 00 6e 00 20 00 75 00 73 00 62 00 ?? ?? ?? ?? ?? ?? 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 20 00 40 00 ?? ?? ?? ?? ?? ?? 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 3d 00 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_5 = "\\sgminer.conf" wide //weight: 1
        $x_1_6 = "\\ckolivas*.bin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

