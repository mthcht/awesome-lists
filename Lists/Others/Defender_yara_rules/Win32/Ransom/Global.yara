rule Ransom_Win32_Global_B_2147961125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Global.B"
        threat_id = "2147961125"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Global"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-skip-local" wide //weight: 1
        $x_1_2 = "unmounting drive %c: after encryption" wide //weight: 1
        $x_1_3 = "got no path, encrypting all drives." wide //weight: 1
        $x_2_4 = {00 78 63 72 79 ?? ?? ?? ?? ?? ?? ?? 64 74 65 64 ?? ?? ?? ?? ?? ?? ?? 6e 6f 74 73 ?? ?? ?? ?? ?? ?? ?? 74 69 6c 6c ?? ?? ?? ?? ?? ?? ?? 5f 61 6d 61 ?? ?? ?? ?? ?? ?? ?? 7a 69 6e 67}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Global_A_2147961916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Global.A"
        threat_id = "2147961916"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Global"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 20 00 64 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 3a 00 20 00 25 00 73 00 20 00 28 00 46 00 69 00 6c 00 65 00 73 00 3a 00 20 00 25 00 6c 00 6c 00 75 00 2c 00 20 00 42 00 79 00 74 00 65 00 73 00 3a 00 20 00 25 00 2e 00 32 00 66 00 20 00 4d 00 42 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 61 00 6c 00 6c 00 6f 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 20 00 66 00 6f 00 72 00 20 00 67 00 5f 00 72 00 6f 00 6f 00 74 00 5f 00 70 00 61 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 74 00 61 00 72 00 74 00 69 00 6e 00 67 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 3a 00 20 00 28 00 66 00 69 00 6c 00 65 00 73 00 20 00 3c 00 3d 00 20 00 35 00 4d 00 42 00 20 00 31 00 30 00 30 00 25 00 25 00 2c 00 20 00 3e 00 20 00 35 00 4d 00 42 00 20 00 32 00 30 00 25 00 25 00 29 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {6c 00 6f 00 63 00 61 00 6c 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 64 00 21 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 00 69 00 6c 00 6c 00 65 00 64 00 20 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 3a 00 20 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

