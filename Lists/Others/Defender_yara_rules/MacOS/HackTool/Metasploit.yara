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

rule HackTool_MacOS_Metasploit_P5_2147959980_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P5"
        threat_id = "2147959980"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05}  //weight: 2, accuracy: High
        $x_2_2 = {b8 6a 00 00 02 48 31 f6 48 ff c6 49 89 fc 0f 05 b8 1e 00 00 02 4c 89 e7 48 89 e6 48 89 e2 48 83 ea 04 0f 05}  //weight: 2, accuracy: High
        $x_2_3 = {b8 1d 00 00 02 48 31 c9 51 48 89 e6 ba 04 00 00 00 4d 31 c0 4d 31 d2 0f 05}  //weight: 2, accuracy: High
        $x_2_4 = {b8 c5 00 00 02 48 31 ff 48 ff cf ba 07 00 00 00 41 ba 02 10 00 00 49 89 f8 4d 31 c9 0f 05 48 89 c6 56}  //weight: 2, accuracy: High
        $x_2_5 = {4c 89 ef 48 31 c9 4c 89 da 4d 31 c0 4d 31 d2 b8 1d 00 00 02 0f 05 58 ff d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P6_2147959981_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P6"
        threat_id = "2147959981"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05}  //weight: 2, accuracy: High
        $x_2_2 = {56 48 89 e6 6a 10 5a 0f 05 b8 6a 00 00 02 48 31 f6 48 ff c6 49 89 fc 0f 05 b8 1e 00 00 02 4c 89 e7 48 89 e6 48 89 e2 48 83 ea 04 0f 05}  //weight: 2, accuracy: High
        $x_2_3 = {48 89 c7 b8 5a 00 00 02 48 31 f6 0f 05 b8 5a 00 00 02 48 ff c6 0f 05 48 31 c0 b8 3b 00 00 02 e8 08 00 00 00}  //weight: 2, accuracy: High
        $x_2_4 = {48 8b 3c 24 48 31 d2 52 57 48 89 e6 0f 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P7_2147959982_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P7"
        threat_id = "2147959982"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 31 ff 57 48 89 e6 6a 04 5a 48 8d 4a fe 4d 31 c0 4d 31 c9 48 ff cf}  //weight: 2, accuracy: High
        $x_2_2 = {48 ff c7 b8 1d 00 00 02 0f 05 81 3c 24 4e 45 4d 4f 75 ed 48 31 c9 b8 1d 00 00 02 0f 05 b8 5a 00 00 02 48 31 f6 0f 05 b8 5a 00 00 02 48 ff c6 0f 05 48 31 c0 b8 3b 00 00 02 e8 08 00 00 00}  //weight: 2, accuracy: High
        $x_2_3 = {48 8b 3c 24 48 31 d2 52 57 48 89 e6 0f 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P8_2147959983_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P8"
        threat_id = "2147959983"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 61 00 00 02 6a 02 5f 6a 01 5e 48 31 d2 0f 05 49 89 c4 48 89 c7 b8 62 00 00 02 48 31 f6 56}  //weight: 2, accuracy: High
        $x_2_2 = {56 48 89 e6 6a 10 5a 0f 05}  //weight: 2, accuracy: High
        $x_2_3 = {b8 5a 00 00 02 48 c7 c6 02 00 00 00 0f 05 b8 5a 00 00 02 48 c7 c6 01 00 00 00 0f 05 b8 5a 00 00 02 48 c7 c6 00 00 00 00 0f 05}  //weight: 2, accuracy: High
        $x_2_4 = {48 31 c0 b8 3b 00 00 02 e8 09 00 00 00}  //weight: 2, accuracy: High
        $x_2_5 = {5f 48 31 d2 52 57 48 89 e6 0f 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P9_2147960210_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P9"
        threat_id = "2147960210"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c0 99 50 40 50 40 50 52 b0 61 cd 80 72 6c 89 c7}  //weight: 2, accuracy: High
        $x_2_2 = {89 e3 6a 10 53 57 52 b0 62 cd 80 72 51}  //weight: 2, accuracy: High
        $x_2_3 = {89 e5 83 ec 08 31 c9 f7 e1 51 89 e6 b0 04 50 56 57 50 48 cd 80}  //weight: 2, accuracy: High
        $x_2_4 = {31 c0 50 50 48 50 40 66 b8 02 10 50 31 c0 b0 07 50 56 52 52 b0 c5 cd 80}  //weight: 2, accuracy: High
        $x_2_5 = {56 89 d8 29 f0 50 57 52 31 c0 b0 03 cd 80 72 08 29 c3 29 c6 75 ea}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P10_2147960211_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P10"
        threat_id = "2147960211"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c0 50 89 e7 6a 10 54 57 50 50}  //weight: 2, accuracy: High
        $x_2_2 = {58 58 40 50 50 6a 1f 58 cd 80}  //weight: 2, accuracy: High
        $x_2_3 = {6a 5a 58 cd 80 ff 4f f0 79 f6}  //weight: 2, accuracy: High
        $x_2_4 = {89 e3 50 54 54 53 50 b0 3b cd 80}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P11_2147960212_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P11"
        threat_id = "2147960212"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c0 99 50 40 50 40 50 52 b0 61 cd 80 0f 82 7e 00 00 00 89 c6}  //weight: 2, accuracy: High
        $x_2_2 = {89 e3 6a 10 53 56 52 b0 68 cd 80 72 67}  //weight: 2, accuracy: High
        $x_2_3 = {52 56 52 b0 6a cd 80 72 5e 52 52 56 52 b0 1e cd 80}  //weight: 2, accuracy: High
        $x_2_4 = {31 db 83 eb 01 43 53 57 53 b0 5a cd 80 72 43 83 fb 03 75 f1}  //weight: 2, accuracy: High
        $x_2_5 = {89 e3 50 50 53 50 b0 3b cd 80}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P12_2147960213_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P12"
        threat_id = "2147960213"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 c0 99 50 40 50 40 50 52 b0 61 cd 80 72 6d 89 c7}  //weight: 2, accuracy: High
        $x_2_2 = {89 e3 6a 10 53 57 52 b0 62 cd 80 72 52}  //weight: 2, accuracy: High
        $x_2_3 = {31 db 83 eb 01 43 53 57 53 b0 5a cd 80 72 43 83 fb 03 75 f1}  //weight: 2, accuracy: High
        $x_2_4 = {31 c0 50 50 50 50 b0 3b cd 80}  //weight: 2, accuracy: High
        $x_2_5 = {89 e3 50 50 53 50 b0 3b cd 80 31 c0 50 89 e3 50 50 53 50 50 b0 07 cd 80}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P14_2147960372_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P14"
        threat_id = "2147960372"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c5 c0 a0 e3 00 00 20 e0 02 15 a0 e3 07 20 a0 e3 01 3a a0 e3 00 40 e0 e3 05 50 25 e0 80 00 00 ef 00 b0 a0 e1 02 00 a0 e3 01 10 a0 e3 06 20 a0 e3 61 c0 a0 e3 80 00 00 ef 00 a0 a0 e1}  //weight: 2, accuracy: High
        $x_2_2 = {10 20 a0 e3 68 c0 a0 e3 80 00 00 ef 0a 00 a0 e1 01 10 a0 e3 6a c0 a0 e3 80 00 00 ef 1e c0 a0 e3 0a 00 a0 e1 10 10 a0 e3 18 10 0d e5 10 20 4d e2 18 30 4d e2 80 00 00 ef}  //weight: 2, accuracy: High
        $x_2_3 = {0a 00 a0 e1 06 c0 a0 e3 80 00 00 ef 07 a0 a0 e1 03 c0 a0 e3 0a 00 a0 e1 0b 10 a0 e1 04 20 a0 e3 80 00 00 ef 00 90 9b e4 0b 80 a0 e1}  //weight: 2, accuracy: High
        $x_2_4 = {03 c0 a0 e3 0a 00 a0 e1 08 10 a0 e1 09 20 a0 e1 80 00 00 ef 00 00 50 e3 04 00 00 ba 00 80 88 e0 00 90 49 e0 00 00 59 e3 f4 ff ff 1a 00 f0 8b e2 01 c0 a0 e3 80 00 00 ef}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P15_2147960373_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P15"
        threat_id = "2147960373"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c5 c0 a0 e3 00 00 20 e0 02 15 a0 e3 07 20 a0 e3 01 3a a0 e3 00 40 e0 e3 05 50 25 e0 80 00 00 ef 00 b0 a0 e1}  //weight: 2, accuracy: High
        $x_2_2 = {02 00 a0 e3 01 10 a0 e3 06 20 a0 e3 61 c0 a0 e3 80 00 00 ef 00 a0 a0 e1}  //weight: 2, accuracy: High
        $x_2_3 = {10 20 a0 e3 62 c0 a0 e3 80 00 00 ef 00 00 50 e3 12 00 00 1a 03 c0 a0 e3 0a 00 a0 e1 0b 10 a0 e1 04 20 a0 e3 80 00 00 ef 00 90 9b e4 0b 80 a0 e1}  //weight: 2, accuracy: High
        $x_2_4 = {03 c0 a0 e3 0a 00 a0 e1 08 10 a0 e1 09 20 a0 e1 80 00 00 ef 00 00 50 e3 04 00 00 ba 00 80 88 e0 00 90 49 e0 00 00 59 e3 f4 ff ff 1a 00 f0 8b e2 01 c0 a0 e3 80 00 00 ef}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MacOS_Metasploit_P16_2147960374_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Metasploit.P16"
        threat_id = "2147960374"
        type = "HackTool"
        platform = "MacOS: "
        family = "Metasploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 00 a0 e3 01 10 a0 e3 06 20 a0 e3 61 c0 a0 e3 80 00 00 ef 00 a0 a0 e1}  //weight: 2, accuracy: High
        $x_2_2 = {0a 00 a0 e1 0e 10 a0 e1 10 20 a0 e3 68 c0 a0 e3 80 00 00 ef 0a 00 a0 e1 01 10 a0 e3 6a c0 a0 e3 80 00 00 ef}  //weight: 2, accuracy: High
        $x_2_3 = {1e c0 a0 e3 0a 00 a0 e1 10 10 a0 e3 18 10 0d e5 10 20 4d e2 18 30 4d e2 80 00 00 ef 00 b0 a0 e1 02 50 a0 e3 5a c0 a0 e3 0b 00 a0 e1 05 10 a0 e1 80 00 00 ef}  //weight: 2, accuracy: High
        $x_2_4 = {05 50 45 e0 0d 60 a0 e1 20 d0 4d e2 14 00 8f e2 00 00 86 e4 04 50 86 e5 06 10 a0 e1 00 20 a0 e3 3b c0 a0 e3 80 00 00 ef}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

