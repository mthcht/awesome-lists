rule Backdoor_Win32_Protux_A_2147628667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Protux.A!dll"
        threat_id = "2147628667"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Protux"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 65 72 73 69 6f 6e 5c 52 75 6e 00 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 6c 00 3e 20 6e 75 6c 00 00 00 46 75 63 6b 00 00 00 00 4b 69 73 32 30 30 39 00}  //weight: 1, accuracy: High
        $x_1_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 54 53 74 61 72 74 55 70 20 30 78 32 32 20 25 73 00 00 25 73 25 64}  //weight: 1, accuracy: High
        $x_1_4 = {57 69 6e 4e 54 20 00 00 5c 68 6f 6e 67 7a 71 75 69 74 2e 64 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Protux_B_2147645447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Protux.B!dll"
        threat_id = "2147645447"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Protux"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "POST http://%s:%d/%s HTTP/1.1" ascii //weight: 1
        $x_1_2 = "HTTPHeader:%s,nRecved:%d" ascii //weight: 1
        $x_10_3 = {68 6f 6e 67 7a 69 6e 73 74 00 00 00 6a 71 79 2e 64 61 74 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Protux_B_2147645447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Protux.B!dll"
        threat_id = "2147645447"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Protux"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 65 72 73 00 00 00 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 54 53 74 61 72 74 55 70 20 30 78 32 32 20 25 73 00 00 25 73 5c 00 25 64}  //weight: 1, accuracy: High
        $x_1_3 = {57 69 6e 4e 54 20 00 00 2d 4d 69 6e 69 42 75 69 6c 64 00 00 69 74 2e 64 61 74 00 00 7a 71 75 00 5c 68 6f 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Protux_C_2147733524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Protux.C!bit"
        threat_id = "2147733524"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Protux"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 55 10 30 14 08 40 3b 45 0c 72 f4}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 08 03 c1 80 30 ?? 41 3b 4d 0c 7c f2}  //weight: 2, accuracy: Low
        $x_1_3 = "User Get IE Proxy Failed" ascii //weight: 1
        $x_1_4 = "WinHttpGetIEProxyConfig error:%d" ascii //weight: 1
        $x_1_5 = "~DF3bbs.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

