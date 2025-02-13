rule HackTool_Win32_PowerSploit_A_2147725414_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PowerSploit.A"
        threat_id = "2147725414"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0}  //weight: 1, accuracy: High
        $x_1_2 = {e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2}  //weight: 1, accuracy: High
        $x_1_3 = {50 68 31 8b 6f 87 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {bb 47 13 72 6f 6a 00 53 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_PowerSploit_A_2147725414_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PowerSploit.A"
        threat_id = "2147725414"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerSploit"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed}  //weight: 1, accuracy: High
        $x_1_2 = {e3 56 48 ff c9 41 8b 34 88 48 01 d6 4d 31 c9 48 31 c0 ac 41 c1 c9 0d 41 01 c1 38 e0 75 f1 4c 03 4c 24 08 45 39 d1 75 d8}  //weight: 1, accuracy: High
        $x_1_3 = {41 ba 31 8b 6f 87 ff d5}  //weight: 1, accuracy: High
        $x_1_4 = {bb e0 1d 2a 0a 41 ba a6 95 bd 9d ff d5}  //weight: 1, accuracy: High
        $x_1_5 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

