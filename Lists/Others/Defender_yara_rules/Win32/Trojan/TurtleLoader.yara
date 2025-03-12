rule Trojan_Win32_TurtleLoader_CS_2147779045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.CS!dha"
        threat_id = "2147779045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 eb 86 5d 68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurtleLoader_RPN_2147828100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.RPN!MTB"
        threat_id = "2147828100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7d 1a 89 c8 99 f7 ff 8b 45 10 8a 04 10 8b 55 08 32 04 0a 88 04 0a 88 04 0b 41 eb e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurtleLoader_R_2147832786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.R!dha"
        threat_id = "2147832786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 0f 10 40 e0 83 c1 40 8d 40 40 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f 11 40 a0 0f 10 40 b0 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f}  //weight: 1, accuracy: High
        $x_1_2 = {11 40 b0 0f 10 40 c0 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f 11 40 c0 0f 10 40 d0 66 0f f8 c1 66 0f ef c1 66 0f fc c1 0f 11 40 d0}  //weight: 1, accuracy: High
        $x_1_3 = {8a 04 31 2c 2a 34 2a 04 2a 88 04 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurtleLoader_PEL_2147848406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.PEL!dha"
        threat_id = "2147848406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinHTTP Example/1.0" wide //weight: 1
        $x_1_2 = "Failed in retrieving the Shellcode" ascii //weight: 1
        $x_1_3 = "[+] Decrypt the PE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurtleLoader_DCG_2147893683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.DCG!dha"
        threat_id = "2147893683"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 6e d8 f8 ff b8 7c ac 47 00 e8 28 dd f8 ff a3 84 ac 47 00 68 74 ac 47 00 6a 40 a1 7c ac 47}  //weight: 1, accuracy: High
        $x_1_2 = {50 a1 84 ac 47 00 50 e8 0a ff f8 ff a1 84 ac 47 00 a3 88 ac 47 00 ff 15 88 ac 47 00}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Windows\\data.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_TurtleLoader_DCH_2147893757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.DCH!dha"
        threat_id = "2147893757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Windows\\data.bin" ascii //weight: 1
        $x_1_2 = "debugconnectwide" ascii //weight: 1
        $x_1_3 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=" ascii //weight: 1
        $x_1_4 = {80 e1 0f c1 e1 04 8a 5d ?? 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb}  //weight: 1, accuracy: Low
        $x_1_5 = {80 e1 3f c1 e1 02 8a 5d ?? 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_TurtleLoader_PAL_2147909463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.PAL!dha"
        threat_id = "2147909463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PAYLOAD" wide //weight: 1
        $x_1_2 = "InitiateTheAttack" ascii //weight: 1
        $x_1_3 = "DllLoader" ascii //weight: 1
        $x_1_4 = "Replace with your payload file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_TurtleLoader_Q_2147935844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoader.Q"
        threat_id = "2147935844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exception occurred during shellcode execution" ascii //weight: 1
        $x_1_2 = "Useless string:" ascii //weight: 1
        $x_1_3 = "Failed to load and execute shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

