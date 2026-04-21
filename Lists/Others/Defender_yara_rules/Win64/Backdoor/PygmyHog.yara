rule Backdoor_Win64_PygmyHog_A_2147967363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PygmyHog.A!dha"
        threat_id = "2147967363"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PygmyHog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "=== Othello (auto-play) starting ===" ascii //weight: 1
        $x_1_2 = "\"process_name\":\"agent-" ascii //weight: 1
        $x_1_3 = "failed to set pipe information" ascii //weight: 1
        $x_1_4 = "failed to decode upload data" ascii //weight: 1
        $x_1_5 = "failed to encode powershell command" ascii //weight: 1
        $x_1_6 = "failed to base64 encode powershell command" ascii //weight: 1
        $x_1_7 = "failed to write dest file" ascii //weight: 1
        $x_1_8 = "failed to start shell" ascii //weight: 1
        $x_1_9 = {48 69 ff 6d 4e c6 41 48 81 c7 39 30 00 00 48 8b cf 48 c1 e9 10 83 e1 0f ba 30 00 00 00 83 f9 0a 66 0f 43 d6 66 03 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win64_PygmyHog_B_2147967365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/PygmyHog.B!dha"
        threat_id = "2147967365"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "PygmyHog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2c 22 74 61 67 22 3a 22 00}  //weight: 1, accuracy: High
        $x_1_2 = {2c 22 63 74 22 3a 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 00 68 00 6f 00 6d 00 65 00 00 00 00 00 00 00 2f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

