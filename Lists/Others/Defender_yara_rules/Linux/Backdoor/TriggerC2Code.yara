rule Backdoor_Linux_TriggerC2Code_A_2147783501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/TriggerC2Code.gen!A!!TriggerC2Code.gen!A"
        threat_id = "2147783501"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "TriggerC2Code"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "TriggerC2Code: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 83 ec 06 6a 02 48 c7 c0 2a 00 00 00 48 89 ef 6a 10 5a 48 89 e6 0f 05 48 81 ec 04 04 00 00 48 31 c0 48 c7 c0 09 00 00 00 48 31 ff 48 c7 c6 00 04 00 00 48 c7 c2 07 00 00 00 48 c7 c1 21 00 00 00 49 89 ca 49 c7 c0 ff ff ff ff 4d 31 c9 0f 05 48 89 04 24 48 c7 c0 00 00 00 00 48 89 ef 68 00 04 00 00 5a 48 8b 34 24 48 83 c6 08 0f 05 48 8b 0c 24 48 89 01 48 c7 c0 01 00 00 00}  //weight: 4, accuracy: High
        $x_2_2 = {6a 01 5f 48 8b 14 24 48 8b 12 48 8b 34 24 48 83 c6 08 0f 05 4c 8b 0c 24 49 83 c1 08 41 51 41 51 c3 48 c7 c0 0b 00 00 00 48 89 cf 48 c7 c6 00 04 00 00 0f 05 48 c7 c0 03 00 00 00 48 89 e7 0f 05 48 c7 c0 3c 00 00 00 48 c7 c7 00 00 00 00 0f 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

