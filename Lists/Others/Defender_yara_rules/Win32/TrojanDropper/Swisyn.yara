rule TrojanDropper_Win32_Swisyn_A_2147629833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swisyn.A"
        threat_id = "2147629833"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kkc-12kdmqdj" ascii //weight: 1
        $x_1_2 = "swdsmnBc`dqgSsdF" ascii //weight: 1
        $x_1_3 = "swdsmnBc`dqgSsdR" ascii //weight: 1
        $x_1_4 = "@rrdbnqOds`dqB" ascii //weight: 1
        $x_1_5 = "wDbnkk@k`tsqhU" ascii //weight: 1
        $x_1_6 = "@dbqtnrdQcmhE" ascii //weight: 1
        $x_1_7 = "dbqtnrdQendyhR" ascii //weight: 1
        $x_1_8 = "dbqtnrdQc`nK" ascii //weight: 1
        $x_1_9 = "dbqtnrdQjbnK" ascii //weight: 1
        $x_1_10 = "dbqtnrdQddqE" ascii //weight: 1
        $x_1_11 = "@rdl`MdbqtnrdQltmD" ascii //weight: 1
        $x_1_12 = "@xqnsbdqhCldsrxRsdF" ascii //weight: 1
        $x_1_13 = "@gs`OoldSsdF" ascii //weight: 1
        $x_1_14 = "@xqnsbdqhCrvncmhVsdF" ascii //weight: 1
        $x_1_15 = "dcnLqnqqDsdR" ascii //weight: 1
        $x_1_16 = "@dmhKcm`llnBsdF" ascii //weight: 1
        $x_1_17 = "@dkhEdsdkdC" ascii //weight: 1
        $x_1_18 = "@dkhEds`dqB" ascii //weight: 1
        $x_1_19 = "dkhEc`dQ" ascii //weight: 1
        $x_1_20 = "dkhEdshqV" ascii //weight: 1
        $x_1_21 = "dkcm`GdrnkB" ascii //weight: 1
        $x_1_22 = "qdsmhnOdkhEsdR" ascii //weight: 1
        $x_1_23 = "kkc-okgdf`lh" ascii //weight: 1
        $x_1_24 = "rsrhwDgs`OxqnsbdqhCdqtRdj`L" ascii //weight: 1
        $x_1_25 = "kkc-12kkdgr" ascii //weight: 1
        $x_1_26 = "@dstbdwDkkdgR" ascii //weight: 1
        $x_1_27 = "@dka`stbdwDcmhE" ascii //weight: 1
        $x_1_28 = "@gs`OqdcknEk`hbdoRsdFGR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (25 of ($x*))
}

rule TrojanDropper_Win32_Swisyn_C_2147631913_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swisyn.C"
        threat_id = "2147631913"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zypsQuofsbqtobsUnputvDeJc" ascii //weight: 1
        $x_1_2 = "tmpdpupsQthojsuTfdsvptfSeJ|" ascii //weight: 1
        $x_1_3 = "tmpdpupsQmbcpmHeJu" ascii //weight: 1
        $x_1_4 = "fspDthojsuTfdsvptfSeJc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Swisyn_D_2147643155_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swisyn.D"
        threat_id = "2147643155"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\insidetm" ascii //weight: 2
        $x_2_2 = "dir_watch.dll" ascii //weight: 2
        $x_3_3 = "kkc-12kdmqdj" ascii //weight: 3
        $x_4_4 = "@rrdbnqOds`dqB" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Swisyn_F_2147657464_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swisyn.F"
        threat_id = "2147657464"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AreFileApisAd.exe" ascii //weight: 1
        $x_1_2 = "Bts and Set" ascii //weight: 1
        $x_1_3 = "/c attrib -R -H -S \"%s\"" ascii //weight: 1
        $x_1_4 = "Windows\\%s.scr" ascii //weight: 1
        $x_1_5 = "Pin this program to taskbar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Swisyn_G_2147670890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Swisyn.G"
        threat_id = "2147670890"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Swisyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 b8 0b 00 00 51 ?? ?? ?? 85 c0 74 5a 33 c0 8a 54 04 ?? 80 f2 ?? 80 ea ?? 80 f2 ?? 88 54 04 ?? 40 3d b8 0b 00 00 7c e7}  //weight: 5, accuracy: Low
        $x_5_2 = {4d 5a 00 00 77 62 00 [0-16] 2e 48 00 00 6f 63 78 00}  //weight: 5, accuracy: Low
        $x_1_3 = {00 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c}  //weight: 1, accuracy: High
        $x_1_4 = {00 78 69 61 6f 68 75 2e 6a 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 62 69 6e 64 2e 61 75 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 6d 75 74 69 2e 61 75 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 63 73 62 6f 79 62 69 6e 64 2e 61 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

