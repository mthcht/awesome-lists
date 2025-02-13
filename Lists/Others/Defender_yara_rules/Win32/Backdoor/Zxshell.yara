rule Backdoor_Win32_Zxshell_A_2147707046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zxshell.A!dha"
        threat_id = "2147707046"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zxshell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZXSockProxy [-b] <Port> [-u] <Username> [-p] <Password>" ascii //weight: 1
        $x_1_2 = {72 75 6e 61 73 20 75 73 65 72 20 70 61 73 73 77 6f 72 64 20 74 65 73 74 2e 65 78 65 20 20 28 72 75 6e 20 74 65 73 74 2e 65 78 65 20 61 73 20 75 73 65 72 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {53 68 61 72 65 53 68 65 6c 6c 20 49 50 20 50 6f 72 74 20 2d 6e 63 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Zxshell_B_2147708597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zxshell.B!dha"
        threat_id = "2147708597"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zxshell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZXNC [-l -f -e <cmd>] [-h <IP>] [-p <Port>] [ quitnc ]" ascii //weight: 1
        $x_1_2 = {5a 58 4e 43 20 2d 65 20 63 6d 64 2e 65 78 65 20 78 2e 78 2e 78 2e 78 20 39 39 20 28 73 65 6e 64 20 61 20 63 6d 64 73 68 65 6c 6c 29 0d 0a}  //weight: 1, accuracy: High
        $x_1_3 = {53 68 61 72 65 53 68 65 6c 6c 20 49 50 20 50 6f 72 74 20 2d 6e 63 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

