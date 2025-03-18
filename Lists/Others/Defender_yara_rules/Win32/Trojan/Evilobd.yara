rule Trojan_Win32_Evilobd_A_2147936321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evilobd.A"
        threat_id = "2147936321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evilobd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 10, accuracy: High
        $x_2_2 = "javascript-obfuscator" ascii //weight: 2
        $x_2_3 = "js-confuser" ascii //weight: 2
        $x_1_4 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 28 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00}  //weight: 1, accuracy: Low
        $x_1_5 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 28 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 29 00 7b 00 72 00 65 00 74 00 75 00 72 00 6e 00 [0-4] 5f 00 30 00 78 00}  //weight: 1, accuracy: Low
        $x_1_6 = {3b 00 77 00 68 00 69 00 6c 00 65 00 28 00 21 00 21 00 5b 00 5d 00 29 00 7b 00 74 00 72 00 79 00 7b 00 76 00 61 00 72 00 [0-4] 5f 00 30 00 78 00 [0-32] 3d 00 70 00 61 00 72 00 73 00 65 00 49 00 6e 00 74 00 28 00 5f 00 30 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Evilobd_B_2147936325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evilobd.B!!Evilobd.B"
        threat_id = "2147936325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evilobd"
        severity = "Critical"
        info = "Evilobd: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "javascript-obfuscator" ascii //weight: 1
        $x_1_2 = "js-confuser" ascii //weight: 1
        $x_1_3 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 28 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 28 00 5f 00 30 00 78 00 [0-32] 2c 00 5f 00 30 00 78 00 [0-32] 29 00 7b 00 72 00 65 00 74 00 75 00 72 00 6e 00 [0-4] 5f 00 30 00 78 00}  //weight: 1, accuracy: Low
        $x_1_5 = {3b 00 77 00 68 00 69 00 6c 00 65 00 28 00 21 00 21 00 5b 00 5d 00 29 00 7b 00 74 00 72 00 79 00 7b 00 76 00 61 00 72 00 [0-4] 5f 00 30 00 78 00 [0-32] 3d 00 70 00 61 00 72 00 73 00 65 00 49 00 6e 00 74 00 28 00 5f 00 30 00 78 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

