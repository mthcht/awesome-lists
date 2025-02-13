rule Trojan_WinNT_Ditul_D_2147597690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Ditul.D"
        threat_id = "2147597690"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Ditul"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PsSetCreateProcessNotifyRoutine" ascii //weight: 1
        $x_2_2 = {81 c3 ec 01 00 00 eb 2d 66 83 ff 03 75 25}  //weight: 2, accuracy: High
        $x_2_3 = {01 00 00 6a 40 68 00 10 00 00 8d 45 f8 50 6a 00 8d 45 d8 50 ff 75 d4 ff 15}  //weight: 2, accuracy: High
        $x_2_4 = {00 10 8b 42 0c 8d 14 24 cd 2e 83 c4 14 89 45 e0 83 7d e0 00 0f 8c}  //weight: 2, accuracy: High
        $x_2_5 = {00 10 8b 42 04 8d 14 24 cd 2e 83 c4 14 89 45 e0 83 7d e0 00 7c}  //weight: 2, accuracy: High
        $x_3_6 = {6a 0a 8d 46 04 50 ff 76 1c e8 ?? ?? ff ff 8d 45 e8 50 8d 45 c4 50 ff 76 14 8d 46 10 50 ff 15}  //weight: 3, accuracy: Low
        $x_3_7 = {8b 06 8b 09 8d 3c 81 57 c7 45 fc 20 00 00 00 ff d3 84 c0 74}  //weight: 3, accuracy: High
        $x_4_8 = {89 1f 0f 20 c0 0d 00 00 01 00 0f 22 c0 8b 7d 0c 8b 45 fc 8b 75 f4}  //weight: 4, accuracy: High
        $x_5_9 = {74 61 8b 1f 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 46 1c 6a 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

