rule Backdoor_Win64_Ruspble_A_2147826380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Ruspble.A"
        threat_id = "2147826380"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Ruspble"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 8a 0c 00 8d 47 01 41 32 0b 99 41 f7 f9 41 32 ca 41 88 0b 8b fa 49 ff c3 44 8a d1 48 83 eb 01}  //weight: 1, accuracy: High
        $x_1_2 = {48 b8 30 2e 30 2e 30 2e 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 b8 11 42 08 21 84 10 42 08}  //weight: 1, accuracy: High
        $x_1_4 = {47 6c 6f 62 ?? ?? ?? ?? 61 6c 5c 25 ?? ?? ?? ?? 30 38 78 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8e 4e 0e ec 74 ?? ?? ?? aa fc 0d 7c 74 ?? ?? ?? 54 ca af 91}  //weight: 1, accuracy: Low
        $x_1_6 = "SystemFunction036" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

