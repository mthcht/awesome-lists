rule PWS_Win32_SocNet_2147628854_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/SocNet"
        threat_id = "2147628854"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "SocNet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 00 00 00 3f 75 73 65 72 3d 00 00 ff ff ff ff 06 00 00 00 26 70 61 73 73 3d 00 00 ff ff ff ff 05 00 00 00 20 20 20 20 20 00 00 00 ff ff ff ff 04 00 00 00 20 20 20 20 00 00 00 00 ff ff ff ff 01 00 00 00 20 00 00 00 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 00 00 00 6f 70 65 6e 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0e 00 00 00 20 2f 53 54 41 52 54 20 51 51 55 49 4e 3a 00 00 ff ff ff ff 09 00 00 00 20 50 57 44 48 41 53 48 3a 00 00 00 ff ff ff ff 07 00 00 00 20 2f 53 54 41 54 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

