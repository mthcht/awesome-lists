rule Worm_Win32_Paiteyello_A_2147640672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Paiteyello.A"
        threat_id = "2147640672"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Paiteyello"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".JPG.exe" wide //weight: 1
        $x_1_2 = "YahooMessenger.exe" wide //weight: 1
        $x_1_3 = "GetDriveTypeA" ascii //weight: 1
        $x_1_4 = {52 00 65 00 6d 00 6f 00 76 00 61 00 62 00 6c 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 20 00 46 00 69 00 78 00 65 00 64 00 20 00 44 00 72 00 69 00 76 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 44 00 72 00 69 00 76 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 20 00 43 00 44 00 2d 00 52 00 4f 00 4d 00 20 00 44 00 72 00 69 00 76 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

