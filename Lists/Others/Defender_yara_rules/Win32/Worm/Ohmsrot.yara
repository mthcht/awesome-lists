rule Worm_Win32_Ohmsrot_A_2147644335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Ohmsrot.A"
        threat_id = "2147644335"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Ohmsrot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 4e 54 49 48 4f 53 54 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 53 56 49 43 48 4f 53 53 54 2e 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {3a 5c 4e 6f 48 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 75 6e 00 00 00 ff ff ff ff 07 00 00 00 6e 6f 68 6f 73 73 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

