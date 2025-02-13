rule Trojan_VBA_Downldr_ARA_2147744582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBA/Downldr.ARA!eml"
        threat_id = "2147744582"
        type = "Trojan"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Downldr"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {70 72 61 6c 74 64 2e 63 6f 6d 2f [0-5] 2e 65 78 65 28 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 3a 2f 2f}  //weight: 10, accuracy: Low
        $x_10_2 = {31 73 74 63 68 6f 69 63 65 70 65 73 74 63 6f 6e 74 72 6f 6c 2e 63 6f 2e 7a 61 2f [0-5] 2e 65 78 65 2b 00 68 74 74 70 3a 2f 2f}  //weight: 10, accuracy: Low
        $x_2_3 = "Sub Document_Open()" ascii //weight: 2
        $x_2_4 = ".CreateTextFile(aaaaaaaa3566sdff, True, True)" ascii //weight: 2
        $x_2_5 = ".ShellExecute (aaaaaaaa3566sdff)" ascii //weight: 2
        $x_2_6 = "Selection.Find.Execute Replace:=wdReplaceAll" ascii //weight: 2
        $x_2_7 = "aaaaaaaa3566s = CreateObject(" ascii //weight: 2
        $x_1_8 = {20 2b 20 49 49 66 28 28 [0-3] 20 2b 20 [0-3] 29 20 3d 20 [0-3] 2c 20 22 [0-5] 22 2c 20 22 56 22 29}  //weight: 1, accuracy: Low
        $x_1_9 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 [0-47] 22 2c 20 [0-47] 2c 20 [0-5] 20 2b 20}  //weight: 1, accuracy: Low
        $x_8_10 = {20 2b 20 49 49 66 28 28 [0-3] 20 2b 20 [0-3] 29 20 3d 20 [0-3] 2c 20 22 [0-5] 22 2c 20 22 [0-10] 22 29}  //weight: 8, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_8_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_VBA_Downldr_CM_2147747914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBA/Downldr.CM!eml"
        threat_id = "2147747914"
        type = "Trojan"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Downldr"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 46 6f 74 6f 73 50 72 6f 64 75 63 74 6f 73 5c 52 65 70 63 6f 6e 38 00 72 75 74 61}  //weight: 1, accuracy: Low
        $x_1_2 = {55 6c 6d 61 5c 52 65 70 63 6f 6e 5f 35 37 5c 28 00 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 63 3a 5c}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 67 65 74 62 61 73 65 6e 61 6d 65 28 64 00 6c 6f 67 46 69 6c 65 6e 61 6d 65 20 3d 20 22 43 3a 5c 74 65 6d 70 5c 22 20 26 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 20 57 73 68 53 68 65 6c 6c 2e 52 75 6e 28 22 70 69 6e 67 20 2d 6e 20 31 20 22 20 26 20 22 [0-25] 22 2c 20 30 2c 20 54 72 75 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_VBA_Downldr_ARO_2147748573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBA/Downldr.ARO!eml"
        threat_id = "2147748573"
        type = "Trojan"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Downldr"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 42 41 2e 47 65 74 4f 62 6a 65 63 74 [0-1] 28 [0-47] 29}  //weight: 1, accuracy: Low
        $x_5_2 = {20 2b 20 49 49 66 28 28 [0-3] 20 2b 20 [0-3] 29 20 3d 20 [0-3] 2c 20 22 [0-5] 22 2c 20 22 [0-10] 22 29}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_VBA_Downldr_CX_2147749833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBA/Downldr.CX!MTB"
        threat_id = "2147749833"
        type = "Trojan"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Downldr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sorryforthe.info/private/HK_Skyline.jpg" ascii //weight: 2
        $x_1_2 = "URLDownloadToFile 0, imgsrc, dlpath & \"HK_Skyline.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

