rule Trojan_Win32_RazerPitch_A_2147730359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RazerPitch.A!dha"
        threat_id = "2147730359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RazerPitch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 81 80 80 80 f7 e1 c1 ea 07 69 d2 ff 00 00 00 2b ca 44 0f b6 c9 30 0f 43 8d 0c 0a b8 81 80 80 80 f7 e1 c1 ea 07 69 d2 ff 00 00 00 2b ca 44 0f b6 d1 30 4f 01 48 83 c7 02 49 ff c8}  //weight: 5, accuracy: High
        $x_5_2 = {48 83 7f 18 08 73 17 4c 8b 47 10 49 ff c0 4d 03 c0 48 8b d7 48 8b cb e8 0b 23 00 00 eb 0d 19 00 48 c7 05 ?? ?? ?? 00 07 00 00 00 48 89 ?? 26 ?? ?? 00 66 89 ?? 0f ?? ?? 00}  //weight: 5, accuracy: Low
        $x_5_3 = {5d 21 1b 07 91 99 2c c5 f5 b7 a9 61 f4 93 77 e3 e3 3f 9a d9 74 4e c2 11 93 e4 b8 9d 56 f3 4a 3e 88 c6 4f 16 65 7b e0 5c 3d 99 d6 70 47 b7 fe b6 b5 6c 22 8e b0 3f ef 2f 1f 4e 6d bb a9 e4 0e f2 0f ec 4e}  //weight: 5, accuracy: High
        $x_1_4 = "wiinsezhsvc" ascii //weight: 1
        $x_1_5 = "Wlytkansvc.dll" ascii //weight: 1
        $x_1_6 = "tLOUenpwIgQWyLmzLsVY.hLNapZYNvtbvrsEIHnuZ" ascii //weight: 1
        $x_1_7 = "KNhzzoLQCMwCZPABtpOR" ascii //weight: 1
        $x_1_8 = "j+I7dx/Lj6/1zKE++jIe5CW7Mh+HgiDHIbYFz1BZSDRCWe5qCB5JS+T5APJCL8so3NTyBjMOAxc8cc+NXa8XWA==" ascii //weight: 1
        $x_1_9 = "t6A2RGv8qam12XnyK+Dc0QteP1+Pake8U+VGUlS1AsHExfy4wxmJjPWZ/3aLrrk4" ascii //weight: 1
        $x_1_10 = "3R5KqFxN/R7Ax5vegYDJmeY+Ih/cKdQt+P5+tifLzSY=" ascii //weight: 1
        $x_1_11 = "6KcizlSVTX/Or3MkAl87DQ==" ascii //weight: 1
        $x_1_12 = "gfUBTITvlj3d1Q424QZaiQ==" ascii //weight: 1
        $x_1_13 = "eP6S86NDlwm9hO9EG//D3g==" ascii //weight: 1
        $x_1_14 = "DEGaz3bb6t3yJzQsOCxAmV069ez4HI86" ascii //weight: 1
        $x_1_15 = "DEGaz3bb6t3yJzQs" ascii //weight: 1
        $x_1_16 = "shpacndsvc" ascii //weight: 1
        $x_1_17 = "Sezlnsrsvc.dll" ascii //weight: 1
        $x_1_18 = "aAhXQMSPvlHNQQKMUqlD.MbGiwiZtPiuvDGsLFGdl" ascii //weight: 1
        $x_1_19 = "ZyCPKNLMVPoKNRYboUdt" ascii //weight: 1
        $x_1_20 = "oj7YSZLdtuJfheZ+24VStgC0zEoi9F6gNozqwWkLkcUR5YkPYfFvs5O+zaY6ZYhOXW24lOMFAiaaT7Ir63U+0Q==" ascii //weight: 1
        $x_1_21 = "BmOOwBqZcMhWIf+ItEFmww9eu96GiC21SLnKiKhMEtHOPRaU5dnrknXOPQ9BdW8V" ascii //weight: 1
        $x_1_22 = "QBKt1JOI1sILSbUR/TiTeV74fm4ygzGQBu5L2P56RqU=" ascii //weight: 1
        $x_1_23 = "xel/D62BOG6SbhVafq9mLQ==" ascii //weight: 1
        $x_1_24 = "2P4ZdZ9d2hjqa4zzftcAdw==" ascii //weight: 1
        $x_1_25 = "nzM+rUT2bjLiFbJCbn43wQ==" ascii //weight: 1
        $x_1_26 = "uofFQ8b6QafYu3wqftLx1kfYvzVWFIBu" ascii //weight: 1
        $x_1_27 = "uofFQ8b6QafYu3wq" ascii //weight: 1
        $x_1_28 = "wbiseplsv" ascii //weight: 1
        $x_1_29 = "Wbyfziosrvc.dll" ascii //weight: 1
        $x_1_30 = "enryPFSjdVEGOngUckvD.fqfFIaGQmBnphvnJUdXP" ascii //weight: 1
        $x_1_31 = "QOQNDljdBCVjiywLtGeL" ascii //weight: 1
        $x_1_32 = "s4+B7W70PD5VI2DicaqwWO73ZOp89gv5nnhSvNgZgeHFGnyyofs6bFyXv/rteiJAk92/NrMJWpwdMMGdgOWmnw==" ascii //weight: 1
        $x_1_33 = "j9QTUDF7XL/J3autHLa2Zp71W7ubYyr+sWRM+rTcwRokEI/LjmGl5//9VO1+4FE7" ascii //weight: 1
        $x_1_34 = "649AiswjYBTxhp04fSG1WM2uTdPxwDyWx+BVGkdwWgA=" ascii //weight: 1
        $x_1_35 = "RNJ70EI7L/jVB5k9YWk4fg==" ascii //weight: 1
        $x_1_36 = "xpTgHTxlz+MzIFFHo+9ITg==" ascii //weight: 1
        $x_1_37 = "ASgwkvdqvJdSsrXnvK6oZg==" ascii //weight: 1
        $x_1_38 = "ayw4XVzqme5ZPBo575XunHk49i194k46" ascii //weight: 1
        $x_1_39 = "ayw4XVzqme5ZPBo5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RazerPitch_B_2147730360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RazerPitch.B!dha"
        threat_id = "2147730360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RazerPitch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 42 fe 48 83 c1 06 83 e0 07 42 0f b6 04 00 30 41 f9 8d 42 ff 83 e0 07 42 0f b6 04 00 30 41 fa 48 8b c2 83 e0 07 42 0f b6 04 00 30 41 fb 8d 42 01 83 e0 07 42 0f b6 04 00 30 41 fc 8d 42 02 83 e0 07 42 0f b6 04 00 30 41 fd 8d 42 03 83 c2 06 83 e0 07 42 0f b6 04 00 30 41 fe 48 ff cf 75 a0}  //weight: 5, accuracy: High
        $x_5_2 = {48 89 84 24 88 00 00 00 48 85 f6 0f 84 c3 00 00 00 66 66 66 66 0f 1f 84 00 00 00 00 00 48 8b 45 00 48 8d 4c 24 20 48 8d 1c 07 48 8b d3 48 8b 03 48 89 84 24 90 00 00 00 48 8b 43 08 48 89 84 24 98 00 00 00 e8 44 fd ff ff 48 8b c3 48 f7 d8 b9 04 00 00 00}  //weight: 5, accuracy: High
        $x_1_3 = "1234567890ABCDEF1234567890ABCDEF" ascii //weight: 1
        $x_1_4 = "Q29upLkEsYeU9eqy8Sfo" wide //weight: 1
        $x_1_5 = "HcI1NJNUqgZ9Pi4U6Gvm.ZmKtveZdduo1XRVXXR1J" ascii //weight: 1
        $x_1_6 = {45 00 62 00 63 00 66 00 46 00 54 00 73 00 47 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "ExnAnqYrF5SCfyyGdcf8eQ==" wide //weight: 1
        $x_1_8 = "QES0ANVwIwjLS+GXLe/9Tw==" wide //weight: 1
        $x_1_9 = "GKVx+dBny8ZMTxS+SPiqwFCEfNXsxdHbfBIaZuu9RZexSZzxt3rc5pgvs6mtc84uhnyiuY9Hqu2R0n0dgJfbAg==" wide //weight: 1
        $x_1_10 = "RTr8uQ5knvmNT+XydyY0OA==" wide //weight: 1
        $x_1_11 = "FXoqoFptkk6fT2UWt4BwQPv1xGa8i3aQZ1qcIt8V0Eaawz63ihvqJVpPqySHf9d1" wide //weight: 1
        $x_1_12 = "2brAP9OppWvpcCPytHtg5d6qY4YaptNByeYUKCgEkdA=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RazerPitch_D_2147730361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RazerPitch.D!dha"
        threat_id = "2147730361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RazerPitch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 81 80 80 80 f7 e1 [0-3] c1 ea 07 69 d2 ff 00 00 00 2b ca 41 [0-8] 44 0f b6 ?? (30 0f|75 d8)}  //weight: 1, accuracy: Low
        $x_1_2 = {6a d4 f8 7b 8f 47 8a a5 96 e9 3a 54 d6 de 95 02 e2 dd c2 4e 12 d7 0c c1 e2 e5 a2 8a c5 44 e2 9c 81 5b ac 4b 15 96 65 ea 0b 9f ab 0e 7d 84 78 f0 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RazerPitch_C_2147730362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RazerPitch.C!dha"
        threat_id = "2147730362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RazerPitch"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 43 5e 41 32 4b 40 41 32 ?? 41 88 4b 40 42 0f b6 04 ?? 41 30 43 41 41 0f b6 43 5f 42 0f b6 04 ?? 41 30 43 42 41 0f b6 43 5c 42 0f b6 04 ?? 41 30 43 43 41 0f b6 ?? 02 c0 45 84 ?? 44 0f b6 ?? 79 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 1f 40 00 66 39 18 74 14 48 83 c0 02 49 ff c9 75 f2 41 ba 57 00 07 80 48 8b cb eb 16 4d 85 c9 75 0b 41 ba 57 00 07 80 48 8b cb eb 06 49 8b c8 49 2b c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

