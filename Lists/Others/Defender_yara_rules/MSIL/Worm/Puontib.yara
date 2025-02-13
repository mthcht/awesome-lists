rule Worm_MSIL_Puontib_A_2147637040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Puontib.A"
        threat_id = "2147637040"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Puontib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {38 30 01 00 00 11 04 11 05 9a 0b 00 07 6f ?? ?? ?? ?? 18 fe 01 16 fe 01 13 06 11 06 3a 0d 01 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = {57 6f 52 6d 59 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 6e 66 65 63 74 44 72 69 76 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Puontib_B_2147664122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Puontib.B"
        threat_id = "2147664122"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Puontib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 11 05 11 05 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? ?? 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 13 ?? 28}  //weight: 1, accuracy: Low
        $x_1_2 = {28 37 00 00 0a 6f 38 00 00 0a 16 9a 0c 28 2e 00 00 0a 0b 72 ?? ?? 00 70 72 ?? ?? 00 70 28 39 00 00 0a 72 ?? ?? 00 70 28 3a 00 00 0a 0a 06 1f 10 28}  //weight: 1, accuracy: Low
        $x_1_3 = {1b 28 31 00 00 0a 72 ?? ?? 00 70 28 32 00 00 0a 73 55 00 00 0a 0a 06 6f 56 00 00 0a 16 6a 18 6f 57 00 00 0a 26 06 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_MSIL_Puontib_C_2147682385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Puontib.C"
        threat_id = "2147682385"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Puontib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 55 53 42 53 70 72 65 61 64 00}  //weight: 10, accuracy: High
        $x_10_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_3 = "autorun.inf" wide //weight: 10
        $x_10_4 = "[autorun]" wide //weight: 10
        $x_1_5 = {00 4c 41 4e 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 59 61 68 6f 6f 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 50 32 50 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 4d 53 4e 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 53 6b 79 70 65 53 70 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_10 = "Keylogger" ascii //weight: 1
        $x_1_11 = {00 52 75 6e 00 47 43 00 4b 65 65 70 41 6c 69 76 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_MSIL_Puontib_D_2147688857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Puontib.D"
        threat_id = "2147688857"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Puontib"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RGlzYWJsZVRhc2tNZ3I=" wide //weight: 1
        $x_1_2 = "RGlzYWJsZVJlZ2lzdHJ5VG9vbHM=" wide //weight: 1
        $x_1_3 = "a2V5c2NyYW1ibGVy" wide //weight: 1
        $x_1_4 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide //weight: 1
        $x_1_5 = "Qzpcd2luZG93c1xzeXN0ZW0zMlxzNGMudmJz" wide //weight: 1
        $x_1_6 = "c2V0IEZydXhyID0gV1NjcmlwdC5DcmVhdGVPYmplY3QoIiJTa3lwZTRDT00uU2t5cGUiIiwgIiJTa3lwZV8iIik=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

