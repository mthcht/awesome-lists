rule Trojan_Win64_Ransom666_A_2147794785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ransom666.A!MTB"
        threat_id = "2147794785"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ransom666"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-37] 2f 00 36 00 36 00 36 00 2e 00 6d 00 70 00 33 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f [0-37] 2f 36 36 36 2e 6d 70 33}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-37] 2f 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 5f 00 61 00 70 00 69 00 2e 00 70 00 68 00 70 00 3f 00 63 00 68 00 65 00 63 00 6b 00 5f 00 70 00 61 00 79 00 6d 00 65 00 6e 00 74 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {68 74 74 70 3a 2f 2f [0-37] 2f 72 61 6e 73 6f 6d 77 61 72 65 5f 61 70 69 2e 70 68 70 3f 63 68 65 63 6b 5f 70 61 79 6d 65 6e 74 3d}  //weight: 1, accuracy: Low
        $x_1_5 = "autorunner.exe" wide //weight: 1
        $x_1_6 = "Your System is now Unlocked" wide //weight: 1
        $x_1_7 = "further_instructions.txt" wide //weight: 1
        $x_1_8 = "Your Soul has been released!" wide //weight: 1
        $x_1_9 = "ransomware.exe" ascii //weight: 1
        $x_1_10 = "666.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

