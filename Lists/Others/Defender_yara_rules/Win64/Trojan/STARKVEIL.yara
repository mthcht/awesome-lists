rule Trojan_Win64_STARKVEIL_DA_2147942426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/STARKVEIL.DA!MTB"
        threat_id = "2147942426"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "STARKVEIL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {41 00 49 00 5f 00 32 00 30 00 32 00 35 00 [0-2] 5f 00 [0-25] 5f 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_2 = {41 49 5f 32 30 32 35 [0-2] 5f [0-25] 5f [0-15] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_3 = {46 00 69 00 6c 00 65 00 5f 00 41 00 49 00 5f 00 [0-25] 5f 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_4 = {46 69 6c 65 5f 41 49 5f [0-25] 5f [0-15] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_5 = {4c 00 75 00 6d 00 61 00 5f 00 32 00 30 00 32 00 35 00 5f 00 [0-25] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_6 = {4c 75 6d 61 5f 32 30 32 35 5f [0-25] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_7 = {4c 00 75 00 6d 00 61 00 41 00 49 00 5f 00 [0-25] 5f 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_8 = {4c 75 6d 61 41 49 5f [0-25] 5f [0-15] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_9 = {4c 00 75 00 6d 00 61 00 6c 00 61 00 62 00 73 00 61 00 69 00 5f 00 [0-25] 5f 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_10 = {4c 75 6d 61 6c 61 62 73 61 69 5f [0-25] 5f [0-15] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_11 = {4c 00 75 00 6d 00 61 00 44 00 72 00 65 00 61 00 6d 00 5f 00 [0-25] 5f 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_12 = {4c 75 6d 61 44 72 65 61 6d 5f [0-25] 5f [0-15] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_13 = {4c 00 75 00 6d 00 61 00 6c 00 61 00 62 00 73 00 5f 00 [0-25] 5f 00 [0-15] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_14 = {4c 75 6d 61 6c 61 62 73 5f [0-25] 5f [0-15] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_15 = {4f 00 4e 00 45 00 4f 00 41 00 49 00 5f 00 4d 00 50 00 34 00 5f 00 [0-25] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_16 = {4f 4e 45 4f 41 49 5f 4d 50 34 5f [0-25] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_17 = {49 00 6e 00 76 00 69 00 64 00 5f 00 48 00 51 00 5f 00 [0-25] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_18 = {49 6e 76 69 64 5f 48 51 5f [0-25] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_100_19 = {4c 00 55 00 4d 00 41 00 [0-15] 5f 00 4d 00 50 00 34 00 5f 00 [0-25] 2e 00 70 00 64 00 62 00}  //weight: 100, accuracy: Low
        $x_100_20 = {4c 55 4d 41 [0-15] 5f 4d 50 34 5f [0-25] 2e 70 64 62}  //weight: 100, accuracy: Low
        $x_1_21 = "ScreenToClient" ascii //weight: 1
        $x_1_22 = "GetKeyboardState" ascii //weight: 1
        $x_1_23 = "SetCapture" ascii //weight: 1
        $x_1_24 = "RevokeDragDrop" ascii //weight: 1
        $x_1_25 = "rust_panic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_STARKVEIL_DB_2147942591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/STARKVEIL.DB!MTB"
        threat_id = "2147942591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "STARKVEIL"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "205"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "C:/winsystem" ascii //weight: 100
        $x_100_2 = "CapCut.pdb" ascii //weight: 100
        $x_1_3 = "ScreenToClient" ascii //weight: 1
        $x_1_4 = "GetKeyboardState" ascii //weight: 1
        $x_1_5 = "SetCapture" ascii //weight: 1
        $x_1_6 = "RevokeDragDrop" ascii //weight: 1
        $x_1_7 = "rust_panic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

