rule TrojanProxy_Win32_Malynfits_A_2147721510_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Malynfits.A"
        threat_id = "2147721510"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Malynfits"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 70 72 6f 78 79 5f 64 6c 6c 2e 64 6c 6c 00 44 6c 6c 52 75 6e 00}  //weight: 2, accuracy: High
        $x_2_2 = "%%BOT_GUID%%" ascii //weight: 2
        $x_2_3 = "%%BOT_API%%" ascii //weight: 2
        $x_2_4 = "fkit.proxy.pipe" ascii //weight: 2
        $x_2_5 = {00 4d 49 54 4d 5f 43 46 47 00}  //weight: 2, accuracy: High
        $x_2_6 = {00 53 65 72 76 65 72 3a 20 6e 67 69 6e 78 0d 0a}  //weight: 2, accuracy: High
        $x_1_7 = {00 25 30 38 78 25 30 34 78 25 30 34 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 25 30 32 78 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 58 2d 52 65 64 69 72 65 63 74 2d 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 7b 22 73 74 61 74 75 73 22 3a 22 6f 6b 22 7d 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 4f 50 54 49 4f 4e 53 00 47 45 54 00 48 45 41 44 00}  //weight: 1, accuracy: High
        $x_2_11 = {00 6d 61 69 6e 36 34 2e 64 6c 6c 00 50 6c 75 67 69 6e 45 6e 74 72 79 00}  //weight: 2, accuracy: High
        $x_2_12 = "fkit.%d.mitm" ascii //weight: 2
        $x_2_13 = "socket.tunnel.%d" ascii //weight: 2
        $x_2_14 = "fkit.x64.helper" ascii //weight: 2
        $x_1_15 = {5c 6c 61 73 74 2e 63 6f 6e 66 00}  //weight: 1, accuracy: High
        $x_1_16 = {5c 6c 75 67 72 61 64 65 34 00}  //weight: 1, accuracy: High
        $x_1_17 = {8b 75 08 c7 05 28 e7 42 00 ?? ?? ?? ?? 80 35 28 e7 42 00 ?? 80 35 2a e7 42 00 ?? 68 ?? ?? ?? ?? 56 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_18 = {bf c5 9d 1c 81 40 69 d7 93 01 00 01}  //weight: 1, accuracy: High
        $x_1_19 = "18550D22-4FCA-4AF2-9E8E-F0259D23694F" ascii //weight: 1
        $x_1_20 = "c4e8d0e1-988d-42b7-bea7-6bf9589bb111" ascii //weight: 1
        $x_1_21 = "rundll32 shell32.dll,ShellExec_RunDLL" ascii //weight: 1
        $x_1_22 = {63 66 67 00 25 00 55 00 53 00 45 00 52 00 50 00}  //weight: 1, accuracy: High
        $x_1_23 = "\\container.dat" ascii //weight: 1
        $x_1_24 = "dropper.path" ascii //weight: 1
        $x_1_25 = "tmp.delete_file" ascii //weight: 1
        $x_1_26 = ".cert_fp" ascii //weight: 1
        $x_1_27 = ".no_install" ascii //weight: 1
        $x_1_28 = ".reg_path" ascii //weight: 1
        $x_1_29 = ".vm_detect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

