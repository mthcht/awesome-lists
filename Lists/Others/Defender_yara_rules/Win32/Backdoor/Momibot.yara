rule Backdoor_Win32_Momibot_B_2147600926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Momibot.gen!B"
        threat_id = "2147600926"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Momibot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {56 6a 14 6a 40 ff 90 ?? ?? 00 00 b9 ?? ?? ?? ?? 8b f0 e8 ?? ?? 00 00 35 57 34 98 12 50 a1 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 ff 90 ?? ?? 00 00}  //weight: 4, accuracy: Low
        $x_4_2 = {85 c0 74 63 a1 ?? ?? ?? ?? 53 83 c6 08 56 ff 90 ?? ?? 00 00 8b f8 8d 47 01 50 a1 0e 00 eb 73 68 ?? ?? ?? ?? 56 ff 90 ?? ?? 00 00}  //weight: 4, accuracy: Low
        $x_1_3 = {5c 64 6c 6c 63 61 63 68 65 5c 74 63 70 69 70 2e 73 79 73 00 5c 53 45 52 56 49 43 45 50 41 43 4b 46 49 4c 45 53 5c 49 33 38 36 5c 74 63 70 69 70 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 49 43 4b 20 25 73 0d 0a 55 53 45 52 20 25 73 20 22 25 73 22 20 22 25 73 22 20 3a 25 73 0d 0a 00 00 00 00 d7 f0 3a ea}  //weight: 1, accuracy: High
        $x_1_5 = {25 73 3b 25 64 3b 25 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {43 4f 4e 46 49 47 53 3a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Momibot_C_2147601107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Momibot.gen!C"
        threat_id = "2147601107"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Momibot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff ff 2e 01 00 00 0f 85 ?? ?? 00 00 68 ?? ?? ?? ?? ff 75 ?? a1 ?? ?? ?? ?? ff 90 ?? ?? 00 00 89 85 ?? ff ff ff 83 bd ?? ff ff ff 00 0f 84}  //weight: 4, accuracy: Low
        $x_4_2 = {39 68 14 74 22 57 e8 ?? 00 00 00 68 ?? ?? ?? ?? 57 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 57 e8 ?? ?? 00 00 57 e8 ?? ?? 00 00 a1}  //weight: 4, accuracy: Low
        $x_4_3 = {39 68 0c 74 22 57 e8 ?? 00 00 00 68 ?? ?? ?? ?? 57 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 57 e8 ?? ?? 00 00 57 e8 ?? ?? 00 00 8b}  //weight: 4, accuracy: Low
        $x_1_4 = {73 70 6f 6f 66 49 50 00}  //weight: 1, accuracy: High
        $x_1_5 = "/ddos/item[@start_t <= '%u' and @stop_t > '%u' and @stat=\"start\"]" ascii //weight: 1
        $x_1_6 = "/ddos/item[@stop_t < '%u' or stat=\"fin\"]" ascii //weight: 1
        $x_1_7 = "/ddos/item[@stat=\"%s\"]" ascii //weight: 1
        $x_1_8 = {69 63 6d 70 5f 64 64 6f 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

