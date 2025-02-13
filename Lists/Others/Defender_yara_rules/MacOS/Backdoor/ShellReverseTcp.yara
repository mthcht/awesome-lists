rule Backdoor_MacOS_ShellReverseTcp_2147745224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/ShellReverseTcp!MTB"
        threat_id = "2147745224"
        type = "Backdoor"
        platform = "MacOS: "
        family = "ShellReverseTcp"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5a c0 a0 e3 0a 00 a0 e1 05 10 a0 e1 80 00 00 ef 01 50 45 e2 00 00 55 e3 f8 ff ff aa 00 00 a0 e3 00 10 a0 e3 7e c0 a0 e3 80 00 00 ef 05 50 45 e0 0d 60 a0 e1 20 d0 4d e2 14 00 8f e2 00 00 86 e4 04 50 86 e5 06 10 a0 e1 00 20 a0 e3 3b c0 a0 e3 80 00 00 ef}  //weight: 2, accuracy: High
        $x_2_2 = {0a 00 a0 e1 0e 10 a0 e1 10 20 a0 e3 62 c0 a0 e3 80 00 00 ef 02 50 a0 e3}  //weight: 2, accuracy: High
        $x_1_3 = "/bin/sh" ascii //weight: 1
        $x_1_4 = "shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

