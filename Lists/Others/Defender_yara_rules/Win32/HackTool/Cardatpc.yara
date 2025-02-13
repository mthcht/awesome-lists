rule HackTool_Win32_Cardatpc_A_2147696826_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Cardatpc.A!dha"
        threat_id = "2147696826"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cardatpc"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--establishnullsession" ascii //weight: 1
        $x_1_2 = {2d 2d 74 65 73 74 34 34 35 00}  //weight: 1, accuracy: High
        $x_1_3 = "cleanlast-desc <word>:" ascii //weight: 1
        $x_1_4 = {2d 2d 66 6f 72 63 65 6c 6f 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Cardatpc_B_2147696827_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Cardatpc.B!dha"
        threat_id = "2147696827"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Cardatpc"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 81 e6 ff 00 00 00 0f b6 44 31 08 03 f8 81 e7 ff 00 00 00 0f b6 5c 39 08 88 5c 31 08 88 44 39 08 02 c3 8b 5d fc 0f b6 c0 8a 44 08 08 32 04 13 42 ff 4d 08 88 42 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8a 4e 01 83 c4 04 80 3e 31}  //weight: 1, accuracy: High
        $x_1_3 = {81 3a 21 21 21 21}  //weight: 1, accuracy: High
        $x_1_4 = "cleanlast-quit <1|0>" ascii //weight: 1
        $x_1_5 = "<PID:USER:DOMAIN:NTLM>" ascii //weight: 1
        $x_1_6 = "\\\\.\\pipe\\lsassp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

