rule Misleading_Win32_Rutspade_240753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Rutspade"
        threat_id = "240753"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Rutspade"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 74 00 61 00 72 00 2d 00 72 00 65 00 70 00 61 00 69 00 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 42 00 6f 00 6f 00 73 00 74 00 53 00 70 00 65 00 65 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00 73 00 00 00 50 00 61 00 72 00 74 00 20 00 6f 00 66 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 53 00 74 00 61 00 72 00 20 00 52 00 65 00 70 00 61 00 69 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

