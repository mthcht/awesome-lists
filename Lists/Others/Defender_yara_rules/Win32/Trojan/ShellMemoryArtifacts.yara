rule Trojan_Win32_ShellMemoryArtifacts_A_2147765692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShellMemoryArtifacts.A"
        threat_id = "2147765692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShellMemoryArtifacts"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 31 c0 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_2 = {48 31 c0 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_3 = {48 31 c9 65 48 8b 08 01 01 01 01 01 01 01 01 41 49 51 59 61 69 71 79 60}  //weight: 10, accuracy: Low
        $x_10_4 = {48 31 c9 65 4c 8b 08 01 01 01 01 01 01 01 01 41 49 51 59 61 69 71 79 60}  //weight: 10, accuracy: Low
        $x_10_5 = {48 31 d2 65 48 8b 08 01 01 01 01 01 01 01 01 42 4a 52 5a 62 6a 72 7a 60}  //weight: 10, accuracy: Low
        $x_10_6 = {48 31 d2 65 4c 8b 08 01 01 01 01 01 01 01 01 42 4a 52 5a 62 6a 72 7a 60}  //weight: 10, accuracy: Low
        $x_10_7 = {48 31 db 65 48 8b 08 01 01 01 01 01 01 01 01 43 4b 53 5b 63 6b 73 7b 60}  //weight: 10, accuracy: Low
        $x_10_8 = {48 31 db 65 4c 8b 08 01 01 01 01 01 01 01 01 43 4b 53 5b 63 6b 73 7b 60}  //weight: 10, accuracy: Low
        $x_10_9 = {4d 31 c0 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_10 = {4d 31 c0 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_11 = {4d 31 c9 65 48 8b 08 01 01 01 01 01 01 01 01 41 49 51 59 61 69 71 79 60}  //weight: 10, accuracy: Low
        $x_10_12 = {4d 31 c9 65 4c 8b 08 01 01 01 01 01 01 01 01 41 49 51 59 61 69 71 79 60}  //weight: 10, accuracy: Low
        $x_10_13 = {4d 31 d2 65 48 8b 08 01 01 01 01 01 01 01 01 42 4a 52 5a 62 6a 72 7a 60}  //weight: 10, accuracy: Low
        $x_10_14 = {4d 31 d2 65 4c 8b 08 01 01 01 01 01 01 01 01 42 4a 52 5a 62 6a 72 7a 60}  //weight: 10, accuracy: Low
        $x_10_15 = {4d 31 db 65 48 8b 08 01 01 01 01 01 01 01 01 43 4b 53 5b 63 6b 73 7b 60}  //weight: 10, accuracy: Low
        $x_10_16 = {4d 31 db 65 4c 8b 08 01 01 01 01 01 01 01 01 43 4b 53 5b 63 6b 73 7b 60}  //weight: 10, accuracy: Low
        $x_10_17 = {4d 31 ed 65 48 8b 08 01 01 01 01 01 01 01 01 45 4d 55 5d 65 6d 75 7d 60}  //weight: 10, accuracy: Low
        $x_10_18 = {4d 31 ed 65 4c 8b 08 01 01 01 01 01 01 01 01 45 4d 55 5d 65 6d 75 7d 60}  //weight: 10, accuracy: Low
        $x_10_19 = {4d 31 f6 65 48 8b 08 01 01 01 01 01 01 01 01 46 4e 56 5e 66 6e 76 7e 60}  //weight: 10, accuracy: Low
        $x_10_20 = {4d 31 f6 65 4c 8b 08 01 01 01 01 01 01 01 01 46 4e 56 5e 66 6e 76 7e 60}  //weight: 10, accuracy: Low
        $x_10_21 = {4d 31 ff 65 48 8b 08 01 01 01 01 01 01 01 01 47 4f 57 5f 67 6f 77 7f 60}  //weight: 10, accuracy: Low
        $x_10_22 = {4d 31 ff 65 4c 8b 08 01 01 01 01 01 01 01 01 47 4f 57 5f 67 6f 77 7f 60}  //weight: 10, accuracy: Low
        $x_10_23 = {48 31 c0 48 f7 e0 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_24 = {48 31 c0 48 f7 e0 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_25 = {48 31 db 48 f7 e3 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_26 = {48 31 db 48 f7 e3 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_27 = {48 31 c9 48 f7 e1 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_28 = {48 31 c9 48 f7 e1 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_29 = {48 31 d2 48 f7 e2 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_30 = {48 31 d2 48 f7 e2 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_31 = {48 31 f6 48 f7 e6 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_32 = {48 31 f6 48 f7 e6 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_33 = {48 31 ff 48 f7 e7 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_34 = {48 31 ff 48 f7 e7 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_35 = {4d 31 c0 49 f7 e0 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_36 = {4d 31 c0 49 f7 e0 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_37 = {4d 31 c9 49 f7 e1 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_38 = {4d 31 c9 49 f7 e1 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_39 = {4d 31 d2 49 f7 e2 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_40 = {4d 31 d2 49 f7 e2 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_41 = {4d 31 db 49 f7 e3 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_42 = {4d 31 db 49 f7 e3 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_43 = {4d 31 e4 49 f7 e4 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_44 = {4d 31 e4 49 f7 e4 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_45 = {4d 31 ed 49 f7 e5 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_46 = {4d 31 ed 49 f7 e5 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_47 = {4d 31 f6 49 f7 e6 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_48 = {4d 31 f6 49 f7 e6 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_49 = {4d 31 ff 49 f7 e7 65 48 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
        $x_10_50 = {4d 31 ff 49 f7 e7 65 4c 8b 08 01 01 01 01 01 01 01 01 40 48 50 58 60 68 70 78 60}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

