rule Backdoor_Win32_Zupdax_A_2147690788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zupdax.A!dha"
        threat_id = "2147690788"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zupdax"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 6f 61 64 5f 73 68 65 6c 6c 63 6f 64 65 20 6d 65 6d 66 69 6e 64 20 70 72 6f 67 72 61 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 79 74 68 72 65 61 64 20 73 74 61 72 74 20 73 6c 65 65 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {6f 70 65 6e 20 66 69 6c 65 20 64 62 20 65 72 72 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 28 73 c6 44 24 29 65 88 5c 24 2a c6 44 24 2b 76 c6 44 24 2c 65 88 5c 24 2d c6 44 24 2e 2e c6 44 24 2f 64 c6 44 24 30 62 89 44 24 31 66 89 44 24 35 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Zupdax_B_2147690789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zupdax.B!dha"
        threat_id = "2147690789"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zupdax"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 00 73 00 5c 00 75 00 70 00 64 00 61 00 74 00 61 00 5c 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "read_dll_memory_load_shellcode" ascii //weight: 1
        $x_1_3 = "Could not open file dll.bin" ascii //weight: 1
        $x_1_4 = "run_transport" wide //weight: 1
        $x_1_5 = "PluginRecvExecuteProc" ascii //weight: 1
        $x_1_6 = "server mythread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

