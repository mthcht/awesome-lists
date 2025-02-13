rule Backdoor_WinNT_PcClient_2147601663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/PcClient"
        threat_id = "2147601663"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "PcClient"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 3, accuracy: High
        $x_3_2 = {68 44 64 6b 20 68 ?? ?? 00 00 6a 01 ff 15}  //weight: 3, accuracy: Low
        $x_2_3 = {81 ea 18 00 61 25 74 ?? 83 ea 08 74 ?? 83 ea 04}  //weight: 2, accuracy: Low
        $x_4_4 = {25 ff ff fe ff 0f 22 c0 8b 41 01 8b ?? ?? ?? 01 00 8b ?? c7 04 81 ?? ?? 01 00 8b}  //weight: 4, accuracy: Low
        $x_5_5 = {25 ff ff fe ff 0f 22 c0 8b 15 ?? ?? 01 00 8b 42 01 8b 0d ?? ?? 01 00 8b 11 c7 04}  //weight: 5, accuracy: Low
        $x_5_6 = {25 ff ff fe ff 0f 22 c0 a1 ?? ?? 01 00 8b 48 01 8b 15 ?? ?? 01 00 8b 02 8b 15}  //weight: 5, accuracy: Low
        $x_5_7 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 [0-8] 01 00 8b ?? 01 8b [0-16] c7 ?? ?? ?? ?? 01 00}  //weight: 5, accuracy: Low
        $x_4_8 = {01 00 8b 40 01 8b 0d ?? ?? 01 00 8b 09 8b 04 81 a3 ?? ?? 01 00 a1 ?? ?? 01 00 8b 40 01 8b 0d ?? ?? 01 00 8b 09 8b 04 81 a3 ?? ?? 01 00 fa}  //weight: 4, accuracy: Low
        $x_2_9 = {01 00 89 14 88 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 2, accuracy: High
        $x_2_10 = {01 00 89 14 81 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 2, accuracy: High
        $x_2_11 = {01 00 89 14 82 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb}  //weight: 2, accuracy: High
        $x_3_12 = {f3 ab 6a 5c 66 ab 5f 6a 53 5e 66 89}  //weight: 3, accuracy: High
        $x_3_13 = {cb c6 45 9c 5c c6 45 9d 52 c6 45 9e 45}  //weight: 3, accuracy: High
        $x_3_14 = {66 ab aa c6 45 4c 5c c6 45 4d 52 c6 45 4e 45}  //weight: 3, accuracy: High
        $x_1_15 = "D:\\Soft\\Smr\\" ascii //weight: 1
        $x_1_16 = "\\pchide\\" ascii //weight: 1
        $x_1_17 = {25 73 25 73 25 73 00 00 25 73 25 73 25 73 00 00 25 73 25 73 25 73}  //weight: 1, accuracy: High
        $x_3_18 = {45 4e 55 4d 5c 52 4f 4f 54 00 00 00 53 45 52 56 49 43 45 53 [0-5] 25 73 25 73 25 73 00 00 25 73 25 73 25 73}  //weight: 3, accuracy: Low
        $x_1_19 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_20 = "PsGetCurrentProcessId" ascii //weight: 1
        $x_1_21 = "ZwQueryDirectoryFile" ascii //weight: 1
        $n_50_22 = "kdefense" ascii //weight: -50
        $n_50_23 = "\\prueba\\miprueba\\Bin\\" ascii //weight: -50
        $n_50_24 = "ActiveX Portector Driver" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 6 of ($x_1_*))) or
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 6 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*))) or
            ((2 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((1 of ($x_5_*) and 2 of ($x_4_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*) and 1 of ($x_4_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

