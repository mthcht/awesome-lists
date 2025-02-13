rule TrojanDropper_Win32_Vbegg_A_2147669018_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Vbegg.A"
        threat_id = "2147669018"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbegg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 50 20 3d 20 6e 75 6d 2b 28 28 38 2d 36 29 2b 28 33 2d 33 29 2b 34 29 [0-2] 50 50 20 3d 20 50 50 2b 31 30 30 30 2d 28 28 34 2a 32 29 2a 31 32 35 29}  //weight: 1, accuracy: Low
        $x_1_2 = "TTTHH.open PP(-6+80) & PP(-6+79) & PP(-6+83) & PP(-6+84)" ascii //weight: 1
        $x_1_3 = {50 78 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 74 65 6d 70 25 22 29 20 26 20 22 5c [0-2] 2e 74 6d 70}  //weight: 1, accuracy: Low
        $x_1_4 = {49 66 20 4e 6f 74 20 46 53 59 2e 46 69 6c 65 45 78 69 73 74 73 28 41 4c 59 59 20 26 20 56 52 46 59 29 20 54 68 65 6e [0-2] 53 65 74 20 57 72 69 74 65 53 74 75 66 66 20 3d 20 46 53 59 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 41 4c 59 59 20 26 20 56 52 46 59 2c 20 38 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

