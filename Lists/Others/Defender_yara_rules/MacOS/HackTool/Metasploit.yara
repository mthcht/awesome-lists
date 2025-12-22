rule HackTool_MacOS_Metasploit_P1_2147959898_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P1"
        threat_id = "2147959898"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {40 00 80 d2 21 00 80 d2 02 00 80 d2 10 40 a0 d2 30 0c 80 f2 01 00 00 d4 ed 03 00 aa}  //weight: 2, accuracy: High
        $x_2_2 = {e1 03 00 91 21 00 02 8b 02 02 80 d2 10 40 a0 d2 10 0d 80 f2 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_3 = {e0 03 0d aa 01 00 80 d2 10 40 a0 d2 50 0d 80 f2 01 00 00 d4 e0 03 0d aa 01 00 80 d2 02 00 80 d2 10 40 a0 d2 d0 03 80 f2 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_4 = {10 40 a0 d2 50 0b 80 f2}  //weight: 2, accuracy: High
        $x_2_5 = {10 40 a0 d2 70 07 80 f2}  //weight: 2, accuracy: High
        $x_1_6 = {5f 6d 6d 61 70 00 5f 6d 70 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P2_2147959899_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P2"
        threat_id = "2147959899"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {42 00 80 d2 43 00 82 d2 e4 03 3f aa e5 03 1f aa d0 07 00 58 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_2 = {40 00 80 d2 21 00 80 d2 02 00 80 d2 b0 06 00 58 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_3 = {01 05 00 10 21 00 40 f9 e1 8f 1f f8 e1 03 00 91 02 02 80 d2 f0 05 00 58 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_4 = {03 08 80 d2 e4 03 1f aa e5 03 1f aa 30 05 00 58 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_5 = {e0 03 0c aa 01 29 80 d2 a2 00 80 d2 d0 04 00 58 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_6 = {63 00 40 f9 e3 0b bf a9 e4 03 00 91 02 00 80 d2 03 00 80 d2 10 03 00 58}  //weight: 2, accuracy: High
        $x_2_7 = {5f 6d 6d 61 70 00 5f 6d 70 72 6f 74 65 63 74 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P4_2147959900_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P4"
        threat_id = "2147959900"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {40 00 80 d2 21 00 80 d2 02 00 80 d2 10 40 a0 d2 30 0c 80 f2 01 00 00 d4 ed 03 00 aa}  //weight: 2, accuracy: High
        $x_2_2 = {e1 8f 1f f8 e1 03 00 91 21 00 02 8b 02 02 80 d2 10 40 a0 d2 50 0c 80 f2 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_3 = {10 40 a0 d2 50 0b 80 f2 e0 03 0d aa 01 00 80 d2 01 00 00 d4 e0 03 0d aa 21 00 80 d2 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_4 = {e1 03 09 aa 21 20 00 d1 21 85 00 f8 3f 85 00 f8 e1 03 09 aa 21 40 00 d1 e2 03 1f aa 01 00 00 d4}  //weight: 2, accuracy: High
        $x_2_5 = {5f 6d 6d 61 70 00 5f 6d 70 72 6f 74 65 63 74 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

