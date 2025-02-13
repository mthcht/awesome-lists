rule Trojan_Win32_Detrahere_B_2147725568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detrahere.B!dr"
        threat_id = "2147725568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detrahere"
        severity = "Critical"
        info = "dr: dropper component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = "a_qTwBHWKFDMkiUmIelJ8yhjb0f4zQO9SxuXAVZ372ELrtG6vCNds5poYn1cgPR" ascii //weight: 20
        $x_20_2 = "RPgc1nYop5sdNCv6GtrLE273ZVAXuxS9OQz4f0bjhy8JleImUikMDFKWHBwTq" ascii //weight: 20
        $x_10_3 = {33 d2 85 f6 ?? ?? 83 c0 03 ?? ?? 83 c0 40 f7 f3 8a 44 15 b8 88 01}  //weight: 10, accuracy: Low
        $x_10_4 = {85 db 74 05 83 c0 fd eb 03 83 c0 46 99}  //weight: 10, accuracy: High
        $x_10_5 = {31 6e 59 6f c7 ?? ?? 70 35 73 64 c7 ?? ?? 4e 43 76 36 c7 ?? ?? 47 74 72 4c}  //weight: 10, accuracy: Low
        $x_10_6 = {44 72 76 50 [0-3] c7 [0-7] 72 6f 74 65 [0-3] c7 [0-7] 63 74 00 00}  //weight: 10, accuracy: Low
        $x_10_7 = {2e 00 5c 00 c7 ?? ?? 44 00 72 00 c7 ?? ?? 76 00 50 00 c7 ?? ?? 72 00 6f 00 c7 ?? ?? 74 00 65 00 c7 ?? ?? 63 00 74 00}  //weight: 10, accuracy: Low
        $x_10_8 = "\\.\\\\DrvProtect" ascii //weight: 10
        $x_10_9 = "rq2cCy8fhLpI4TwCFRCU" wide //weight: 10
        $x_10_10 = "W-rPJbw6LQtmPef5kxqh" wide //weight: 10
        $x_10_11 = "QecTmzgcmfW6SCf4-s5s" wide //weight: 10
        $x_10_12 = "mNyRp6kYH5cUsoNluTCn" wide //weight: 10
        $x_10_13 = {72 00 71 00 c7 [0-3] 32 00 63 00 c7 [0-3] 43 00 79 00 c7 [0-3] 38 00 66 00}  //weight: 10, accuracy: Low
        $x_10_14 = {6d 00 4e 00 c7 [0-3] 79 00 52 00 c7 [0-3] 70 00 36 00 c7 [0-3] 6b 00 59 00 c7 [0-3] 48 00 35 00}  //weight: 10, accuracy: Low
        $x_10_15 = {78 35 31 00 65 00 c7 [0-3] 63 00 54 00 c7 [0-3] 6d 00 7a 00 c7 [0-3] 67 00 63}  //weight: 10, accuracy: Low
        $x_10_16 = {69 6e 73 74 c7 [0-3] 61 00 00 00}  //weight: 10, accuracy: Low
        $x_10_17 = {18 49 67 6f 76 c7 [0-6] 1c 54 00 00 00 8d 51 01}  //weight: 10, accuracy: Low
        $x_10_18 = {6d 38 36 67 c7 ?? ?? 38 79 45 72 c7 ?? ?? 2e 70 79 79}  //weight: 10, accuracy: Low
        $x_10_19 = {43 38 76 37 c7 ?? ?? 38 36 6f 49 c7 ?? ?? 31 67 74 41 66 ?? ?? dc 44 00}  //weight: 10, accuracy: Low
        $x_10_20 = {43 38 76 35 c7 ?? ?? 54 76 49 64 c7 ?? ?? 38 58 62 6f c7 ?? ?? 76 38 6c 4a c7 ?? ?? 67 51 31 00}  //weight: 10, accuracy: Low
        $x_10_21 = {52 00 6a 00 c7 ?? ?? 79 00 55 00 c7 ?? ?? 35 00 46 00 c7 ?? ?? 64 00 79}  //weight: 10, accuracy: Low
        $x_10_22 = "eglTn7I8WxQkIy8" ascii //weight: 10
        $x_10_23 = "JoKTpXv6Ig-/v6D" ascii //weight: 10
        $x_10_24 = "?8-i8y8v87TyV8D" ascii //weight: 10
        $x_10_25 = "C8vs1llTgpGIg8D" ascii //weight: 10
        $x_10_26 = "?8-s68Tv8M8btAD" ascii //weight: 10
        $x_10_27 = "C8vM8b5Tl8H8AvD" ascii //weight: 10
        $x_10_28 = "/61R8ooErkI6ovD" ascii //weight: 10
        $x_10_29 = "DIgFvvn?8TpiTvT" ascii //weight: 10
        $x_10_30 = "i8dIR8J1s1gv61y" ascii //weight: 10
        $x_2_31 = "netfilter3_x64_xp.data" ascii //weight: 2
        $x_2_32 = "netfilter3_x64_win8.data" ascii //weight: 2
        $x_2_33 = "netfilter3_x64_win7.data" ascii //weight: 2
        $x_2_34 = "netfilter3_x86_xp.data" ascii //weight: 2
        $x_2_35 = "netfilter3_x86_win8.data" ascii //weight: 2
        $x_2_36 = "netfilter3_x86_win7.data" ascii //weight: 2
        $x_2_37 = "radardt32.data" ascii //weight: 2
        $x_2_38 = "radardt64.data" ascii //weight: 2
        $x_2_39 = "msidntld32.data" ascii //weight: 2
        $x_2_40 = "msidntld64.data" ascii //weight: 2
        $x_2_41 = "udisk.data" ascii //weight: 2
        $x_2_42 = "atad.px_46x_3retliften" ascii //weight: 2
        $x_2_43 = "atad.8niw_46x_3retliften" ascii //weight: 2
        $x_2_44 = "atad.7niw_46x_3retliften" ascii //weight: 2
        $x_2_45 = "atad.px_68x_3retliften" ascii //weight: 2
        $x_2_46 = "atad.8niw_68x_3retliften" ascii //weight: 2
        $x_2_47 = "atad.7niw_68x_3retliften" ascii //weight: 2
        $x_2_48 = "atad.23tdradar" ascii //weight: 2
        $x_2_49 = "atad.46tdradar" ascii //weight: 2
        $x_2_50 = "atad.23dltndism" ascii //weight: 2
        $x_2_51 = "atad.46dltndism" ascii //weight: 2
        $x_2_52 = "atad.ksidu" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_2_*))) or
            ((1 of ($x_10_*) and 5 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Detrahere_C_2147725569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detrahere.C"
        threat_id = "2147725569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detrahere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\VC_Project\\SmartService\\Release\\splsrv.pdb" ascii //weight: 1
        $x_1_2 = "Global\\splsrv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Detrahere_D_2147725570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detrahere.D"
        threat_id = "2147725570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detrahere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4a 6e 30 79 c7 ?? ?? 6e 54 6e 49 c7 ?? ?? 2e 70 79 79}  //weight: 10, accuracy: Low
        $x_10_2 = {43 38 76 33 c7 ?? ?? 70 54 6e 76 c7 ?? ?? 38 36 6f 33 c7 ?? ?? 70 70 36 38 c7 ?? ?? 6f 6f 38 6f}  //weight: 10, accuracy: Low
        $x_5_3 = {7b 00 41 00 c7 ?? ?? ?? 00 00 00 42 00 45 00 c7 ?? ?? ?? 00 00 00 34 00 37 00 c7 ?? ?? ?? 00 00 00 42 00 37 00 c7 ?? ?? ?? 00 00 00 32 00 2d 00 c7 ?? ?? ?? 00 00 00 30 00 43 00 c7 ?? ?? ?? 00 00 00 32 00 46 00}  //weight: 5, accuracy: Low
        $x_5_4 = {47 00 6c 00 c7 ?? ?? 6f 00 62 00 c7 ?? ?? 61 00 6c 00 c7 ?? ?? 5c 00 53 00 c7 ?? ?? 65 00 74 00 c7 ?? ?? 75 00 70 00 c7 ?? ?? 4d 00 75 00 c7 ?? ?? 74 00 65 00 c7 ?? ?? 78 00 5f 00}  //weight: 5, accuracy: Low
        $x_10_5 = {50 00 72 00 c7 ?? ?? 69 00 6b 00 c7 ?? ?? 72 00 79 00 c7 ?? ?? 6c 00 00 00}  //weight: 10, accuracy: Low
        $x_10_6 = {6d 00 73 00 c7 ?? ?? 69 00 64 00 c7 ?? ?? 6e 00 74 00 c7 ?? ?? 66 00 73 00}  //weight: 10, accuracy: Low
        $x_10_7 = {63 64 6e 2e c7 ?? ?? 6f 70 74 69 c7 ?? ?? 74 63 2e 63 c7 ?? ?? 6f 6d 2f 6a c7 ?? ?? 71 75 65 72 c7 ?? ?? 79 2e 6d 69 c7 ?? ?? 6e 2e 6a 73}  //weight: 10, accuracy: Low
        $x_5_8 = "https://cdn.optitc.com/jquery.min.js" ascii //weight: 5
        $x_5_9 = "{ABE47B72-0C2F-421F-BF5-D86F8ABD3570}" ascii //weight: 5
        $x_10_10 = {46 33 3f 69 40 00 51 3d c7 ?? ?? ?? 00 00 44 33 3f 74 40 00 51 47 c7 ?? ?? ?? 00 00 5c 69 74 58 40 00 51 51 c7 ?? ?? ?? 00 00 73 3f 4a 2f}  //weight: 10, accuracy: Low
        $x_10_11 = {43 38 76 4a 40 00 4c 2a c7 ?? ?? 00 00 00 51 48 54 34 40 00 4c 34 c7 ?? ?? 00 00 00 79 38 72 00}  //weight: 10, accuracy: Low
        $x_5_12 = {7b 00 41 00 c7 ?? ?? 42 00 45 00 c7 ?? ?? 34 00 37 00 c7 ?? ?? 42 00 37 00}  //weight: 5, accuracy: Low
        $x_10_13 = {57 57 2e 56 c7 ?? ?? 6f 38 36 34 c7 ?? ?? 38 6f 76 2e c7 ?? ?? 52 31 6c 71}  //weight: 10, accuracy: Low
        $x_10_14 = {30 76 76 6e c7 ?? ?? 71 61 61 2d c7 ?? ?? 6e 76 75 2e c7 ?? ?? 52 31 6c 61}  //weight: 10, accuracy: Low
        $x_5_15 = "http://optitm.com/client" ascii //weight: 5
        $x_5_16 = "http://gpt9.com/api/cpx?Lq=" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Detrahere_E_2147725571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detrahere.E"
        threat_id = "2147725571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detrahere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Lbtqfstlz!Mbc" ascii //weight: 10
        $x_10_2 = "Nbmxbsfczuft!Dpsqpsbujpo" ascii //weight: 10
        $x_10_3 = "NdBgff-!Jod/" ascii //weight: 10
        $x_10_4 = "Qboeb!Tfdvsjuz!T/M" ascii //weight: 10
        $x_1_5 = "[LR@RBTH-dwd" ascii //weight: 1
        $x_1_6 = "[LRLODMF-DWD" ascii //weight: 1
        $x_1_7 = "[@UFTH-DWD" ascii //weight: 1
        $x_1_8 = "[@UFTHW-DWD" ascii //weight: 1
        $x_1_9 = "[@U@RSRUB-DWD" ascii //weight: 1
        $x_1_10 = "[@U@RSTH-DWD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Detrahere_2147727700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detrahere"
        threat_id = "2147727700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detrahere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7b 00 41 00 c7 84 24 ?? ?? ?? ?? 42 00 45 00 c7 84 24 ?? ?? ?? ?? 34 00 37 00 c7 84 24 ?? ?? ?? ?? 42 00 37 00 c7 84 24 ?? ?? ?? ?? 32 00 2d 00 c7 84 24 ?? ?? ?? ?? 30 00 43 00 c7 84 24 ?? ?? ?? ?? 32 00 46 00 c7 84 24 ?? ?? ?? ?? 2d 00 34 00 c7 84 24 ?? ?? ?? ?? 32 00 31 00 c7 84 24 ?? ?? ?? ?? 46 00 2d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Global\\SetupMutex_" wide //weight: 1
        $x_1_3 = "CChrome_MessagePumpWindow" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Detrahere_2147727700_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detrahere"
        threat_id = "2147727700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detrahere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://gpt9.com/api/cpx?q=" ascii //weight: 1
        $x_1_2 = "Global\\splsrv" ascii //weight: 1
        $x_1_3 = "\\SmartService\\Release\\splsrv.pdb" ascii //weight: 1
        $x_1_4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii //weight: 1
        $x_1_5 = "minkernel\\crts\\ucrt\\inc\\corecrt_internal_strtox.h" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Detrahere_H_2147727711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Detrahere.H"
        threat_id = "2147727711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Detrahere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SVCVMX{72CE8DB0-6EB6-4C24-92E8-A07B77A229F8}" ascii //weight: 1
        $x_1_2 = "E:\\cef_2526\\download\\chromium\\src\\out\\Release\\winltc.exe.pdb" ascii //weight: 1
        $x_1_3 = "SMARTSOFT Copyright (C) svcvmx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

