rule Trojan_Win32_Fobexy_A_2147721550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fobexy.A!bit"
        threat_id = "2147721550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fobexy"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://host87.net" wide //weight: 1
        $x_1_2 = "http://local45.net" wide //weight: 1
        $x_1_3 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide //weight: 1
        $x_1_4 = {61 00 64 00 76 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 72 00 75 00 6c 00 65 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 [0-32] 64 00 69 00 72 00 3d 00 69 00 6e 00 20 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 61 00 6c 00 6c 00 6f 00 77 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 3d 00 22 00 [0-48] 22 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 3d 00 79 00 65 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

