rule Backdoor_Win32_RDPopen_A_2147656536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RDPopen.A"
        threat_id = "2147656536"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RDPopen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 e8 54 99 b9 1a 00 00 00 f7 f9 83 c2 61 8b 45 08 88 10 eb 2f}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 08 0f be 02 85 c0 74 0f 8b 4d 08 8a 11 80 ea 01 8b 45 08 88 10 eb de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_RDPopen_B_2147658924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RDPopen.B"
        threat_id = "2147658924"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RDPopen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 74 65 6d 50 25 00 63 73 72 73 73 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "Window-RPC Hos-Service" ascii //weight: 1
        $x_1_3 = {2b c2 03 45 ?? 99 b9 1a 00 00 00 f7 f9 0f be 45 ?? 03 d0 8b 4d ?? 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_RDPopen_B_2147658924_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/RDPopen.B"
        threat_id = "2147658924"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "RDPopen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 06 6a 01 6a 02 8b 85 ?? ?? ?? ?? 8b 88 84 01 00 00 ff d1}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d0 3d 33 27 00 00 75 ?? 6a 05 8b 4d 08 8b 91 24 01 00 00 ff d2 eb ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_3 = "|gethostname" ascii //weight: 1
        $x_1_4 = "jiefhhfufh" ascii //weight: 1
        $x_1_5 = "hd2h080hch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

