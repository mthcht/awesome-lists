rule Trojan_Win64_Sainbox_A_2147945808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sainbox.A"
        threat_id = "2147945808"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sainbox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "105"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 100, accuracy: High
        $x_1_2 = {76 73 73 65 72 76 2e 65 78 65 [0-16] 2e 65 78 65 [0-16] 2e 65 78 65 [0-16] 2e 65 78 65 [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {47 65 74 44 61 74 61 00 43 3a 5c 55 73 65 72 73 5c}  //weight: 1, accuracy: High
        $x_1_4 = "C:\\Windows\\Temp\\aceprocted.sys" ascii //weight: 1
        $x_1_5 = "reg add \\\" HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii //weight: 1
        $x_1_6 = {53 43 48 54 41 53 4b 53 20 2f 52 75 6e 20 2f 54 4e 20 [0-16] 20 26 20 53 43 48 54 41 53 4b 53 20 2f 44 65 6c 65 74 65 20 2f 54 4e 20 [0-16] 20 2f 46}  //weight: 1, accuracy: Low
        $x_1_7 = {53 43 48 54 41 53 4b 53 20 2f 43 72 65 61 74 65 20 2f 46 20 2f 54 4e 20 [0-16] 20 2f 53 43 20 4f 4e 43 45 20 2f 53 54 20 30 30 3a 30 30 20 2f 52 4c 20 48 49 47 48 45 53 54 20 2f 52 55 20 22 53 59 53 54 45 4d 22}  //weight: 1, accuracy: Low
        $x_1_8 = "Add-MpPreference -ExclusionPath" ascii //weight: 1
        $x_1_9 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 [0-16] 54 43 4c 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_10 = "Music\\destopbak" ascii //weight: 1
        $x_1_11 = "\\Public\\MpDefender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Sainbox_C_2147945910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Sainbox.C"
        threat_id = "2147945910"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Sainbox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\\\.\\TrueSight" wide //weight: 10
        $x_10_2 = {ba 44 e0 22 00 48 8b cb ?? e8}  //weight: 10, accuracy: Low
        $x_10_3 = {45 88 54 06 ff 1a 00 83 fd 04}  //weight: 10, accuracy: Low
        $x_1_4 = {83 fd 0a e9 00 00 00 00 0f 8d 0d 00 00 00 83 ed 03 e9 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {83 fd 0a 0f 8d 0d 00 00 00 83 ed 03 e9 00 00 00 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

