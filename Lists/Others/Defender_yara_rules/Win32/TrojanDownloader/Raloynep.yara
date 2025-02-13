rule TrojanDownloader_Win32_Raloynep_A_2147690876_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Raloynep.A"
        threat_id = "2147690876"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Raloynep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 31 2a d8 42 83 fa 10 88 1c 31 7c 02 33 d2 41 3b cf 7c e4}  //weight: 2, accuracy: High
        $x_2_2 = "XqiuycvkcTjduqvpkv_Xkphu~z]DxtufsvYftumuucFyw^Vfyvloiu" ascii //weight: 2
        $x_1_3 = {80 48 45 47 35 35 49 3c 3c 34 3a 38 48 35 30 35 4b 3b 49 2e 43 38 35 4b 34 3a 33 45 37 34 49 42}  //weight: 1, accuracy: High
        $x_1_4 = {6d 76 77 71 3c 31 33 38 39 39 2f 33 36 38 31 35 39 30 34 36 38 31 82 72 76 79 62 7a 32 71 73 66}  //weight: 1, accuracy: High
        $x_1_5 = {2a 75 75 66 69 75 7a 78 3a 39 21 26 76 22 32 76 25 31 76 00}  //weight: 1, accuracy: High
        $x_1_6 = {2a 75 75 66 69 75 7a 78 3a 39 21 26 76 22 32 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

