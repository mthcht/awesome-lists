rule Backdoor_Win32_Doerbot_A_2147694458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Doerbot.A"
        threat_id = "2147694458"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Doerbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "...I Am The Greatest!!!..." ascii //weight: 5
        $x_5_2 = "Victoryzx" ascii //weight: 5
        $x_5_3 = "JOS-97CFD8159CE" ascii //weight: 5
        $x_5_4 = "\\Desktop\\J19.pdb" ascii //weight: 5
        $x_2_5 = {00 64 65 6c 65 74 65 72 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 70 75 74 65 72 00}  //weight: 2, accuracy: High
        $x_2_7 = {00 73 61 76 65 72 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Doerbot_A_2147694458_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Doerbot.A"
        threat_id = "2147694458"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Doerbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 74 74 70 3a 2f 2f 73 75 70 65 72 76 70 6e 2e 63 6f 2e 75 6b 2f 6d 79 6c 6f 67 2f [0-32] 2e 70 68 70}  //weight: 3, accuracy: Low
        $x_3_2 = "/lala3.php" ascii //weight: 3
        $x_2_3 = "<form method=\"POST\" action=" ascii //weight: 2
        $x_2_4 = {00 63 6d 64 68 69 64 65 00}  //weight: 2, accuracy: High
        $x_2_5 = {00 50 6f 73 74 20 4c 6f 67 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 64 65 6c 65 74 65 72 00}  //weight: 2, accuracy: High
        $x_2_7 = {00 70 75 74 65 72 00}  //weight: 2, accuracy: High
        $x_2_8 = {00 73 61 76 65 72 00}  //weight: 2, accuracy: High
        $x_2_9 = {00 68 74 74 70 70 61 74 68 73 00}  //weight: 2, accuracy: High
        $x_2_10 = "|Payment Document" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_2_*))) or
            ((1 of ($x_3_*) and 6 of ($x_2_*))) or
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            (all of ($x*))
        )
}

