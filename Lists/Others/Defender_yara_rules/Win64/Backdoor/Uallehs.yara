rule Backdoor_Win64_Uallehs_A_2147958618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Uallehs.A"
        threat_id = "2147958618"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Uallehs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "0xd68910ED4D4A5A9bAdF9ec95604CAE0f3378479B" ascii //weight: 2
        $x_2_2 = "a0,80,80,a2,a0,83,8d,96,65,82," ascii //weight: 2
        $x_2_3 = {22 6a 73 6f 6e 72 70 63 22 3a 20 22 32 2e 30 22 2c [0-32] 22 6d 65 74 68 6f 64 22 3a 20 22 65 74 68 5f 63 61 6c 6c 22 2c}  //weight: 2, accuracy: Low
        $x_1_4 = "void* (__stdcall*)(void*, size_t, LPTHREAD_START_ROUTINE, void*, ulong, ulong*)" ascii //weight: 1
        $x_1_5 = "void* (__stdcall*)(void*, pcwstr, pcwstr, pcwstr, pcwstr, pcwstr*, ulong, ulong)" ascii //weight: 1
        $x_1_6 = {74 79 70 65 64 65 66 20 69 6e 74 20 28 5f 5f 73 74 64 63 61 6c 6c 2a 20 46 41 52 50 52 4f 43 29 28 29 3b [0-48] 74 79 70 65 64 65 66 20 75 6e 73 69 67 6e 65 64 20 6c 6f 6e 67 20 28 5f 5f 73 74 64 63 61 6c 6c 2a 20 4c 50 54 48 52 45 41 44 5f 53 54 41 52 54 5f 52 4f 55 54 49 4e 45 29 28 76 6f 69 64 2a 29 3b}  //weight: 1, accuracy: Low
        $x_1_7 = "schtasks /create /sc daily /st %02d:%02d /f" ascii //weight: 1
        $x_1_8 = "X:\\luapower\\csrc\\luajit\\src\\src" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

