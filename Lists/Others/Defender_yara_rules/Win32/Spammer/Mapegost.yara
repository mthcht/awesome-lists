rule Spammer_Win32_Mapegost_A_2147654381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Mapegost.A"
        threat_id = "2147654381"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapegost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 02 66 89 0a 0f b7 08 83 c2 02 83 f9 22 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f be d0 8a 41 01 33 fa 6b ff 71 41 0f cf 84 c0}  //weight: 1, accuracy: High
        $x_1_3 = "spamget.php" ascii //weight: 1
        $x_1_4 = {6d 6f 64 65 3d 67 65 74 [0-8] 26 75 69 64 3d 25 73 26 6f 73 3d 25 73 26 70 69 64 3d 25 73 26 66 6c 61 67 73 3d 25 73 26 73 65 6e 74 3d 25 69 26 61 63 63}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

