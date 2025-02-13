rule Worm_Win32_Kalockan_A_2147714799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Kalockan.A"
        threat_id = "2147714799"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Kalockan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 70 72 6f 73 3d [0-8] 2f 67 61 74 65 5f 75 72 6c 7a 6f 6e 65 2f}  //weight: 1, accuracy: Low
        $x_1_2 = {25 42 4f 54 49 44 25 [0-8] 25 42 4f 54 4e 45 54 25}  //weight: 1, accuracy: Low
        $x_1_3 = {26 69 70 63 6e 66 3d [0-8] 26 73 63 6b 70 6f 72 74 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {25 4c 4f 43 4b 44 4f 4d 41 49 4e 25 [0-8] 25 4c 4f 43 4b 4d 45 53 53 41 47 45 25}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-8] 7c 45 6e 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

