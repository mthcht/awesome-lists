rule Worm_Win32_Yosheetsune_A_2147595672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Yosheetsune.A"
        threat_id = "2147595672"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Yosheetsune"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Documents and Settings\\NEMES1S\\Desktop\\" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\SuperHidden" wide //weight: 1
        $x_1_5 = ":\\PICTURES.exe" wide //weight: 1
        $x_1_6 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00 00 00 00 00 0e 00 00 00 4e 00 6f 00 43 00 6c 00 6f 00 73 00 65 00 00 00 1c 00 00 00 4e 00 6f 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 50 00 61 00 6e 00 65 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

