rule Trojan_Linux_Hades_B_2147975122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Hades.B!AMTB"
        threat_id = "2147975122"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Hades"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 00 61 00 69 00 6e 00 2e 00 73 00 65 00 72 00 76 00 65 00 72 00 55 00 52 00 4c 00 3d 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 34 00 33 00 2e 00 32 00 34 00 36 00 2e 00 32 00 30 00 38 00 2e 00 32 00 30 00 37 00 3a 00 [0-5] 27 00 20 00 2d 00 58 00 20 00 27 00 6d 00 61 00 69 00 6e 00 2e 00 69 00 6d 00 70 00 6c 00 61 00 6e 00 74 00 54 00 6f 00 6b 00 65 00 6e 00 3d 00 [0-64] 3d 00 27 00 20 00 2d 00 58 00 20 00 27 00 6d 00 61 00 69 00 6e 00 2e 00 61 00 65 00 73 00 4b 00 65 00 79 00 42 00 36 00 34 00 3d 00 [0-64] 3d 00}  //weight: 3, accuracy: Low
        $x_3_2 = {6d 61 69 6e 2e 73 65 72 76 65 72 55 52 4c 3d 68 74 74 70 73 3a 2f 2f 34 33 2e 32 34 36 2e 32 30 38 2e 32 30 37 3a [0-5] 27 20 2d 58 20 27 6d 61 69 6e 2e 69 6d 70 6c 61 6e 74 54 6f 6b 65 6e 3d [0-64] 3d 27 20 2d 58 20 27 6d 61 69 6e 2e 61 65 73 4b 65 79 42 36 34 3d [0-64] 3d}  //weight: 3, accuracy: Low
        $x_2_3 = "main.checkInPath=/assets/app.min.js' -X 'main.tasksPath=/assets/vendor.js' -X 'main.resultPath=/assets/main.js" ascii //weight: 2
        $x_1_4 = {6d 00 61 00 69 00 6e 00 2e 00 62 00 75 00 69 00 6c 00 64 00 55 00 41 00 3d 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 31 00 30 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 36 00 34 00 3b 00 20 00 78 00 36 00 34 00 29 00 20 00 41 00 70 00 70 00 6c 00 65 00 57 00 65 00 62 00 4b 00 69 00 74 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 20 00 28 00 4b 00 48 00 54 00 4d 00 4c 00 2c 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 29 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 [0-5] 2e 00 [0-5] 2e 00 [0-5] 2e 00 [0-5] 20 00 53 00 61 00 66 00 61 00 72 00 69 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 61 69 6e 2e 62 75 69 6c 64 55 41 3d 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f [0-5] 2e [0-5] 2e [0-5] 2e [0-5] 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

