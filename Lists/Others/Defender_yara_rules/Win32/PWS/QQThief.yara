rule PWS_Win32_QQThief_C_2147631885_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQThief.C"
        threat_id = "2147631885"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 ce 3f c6 45 cf 61 c6 45 d0 63 c6 45 d1 74 c6 45 d2 69 c6 45 d3 6f c6 45 d4 6e c6 45 d5 3d}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 e9 73 c6 45 ea 6e c6 45 eb 69 c6 45 ec 66 c6 45 ed 66}  //weight: 1, accuracy: High
        $x_1_3 = {71 71 6c 6f 67 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {44 4e 46 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQThief_D_2147632387_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQThief.D"
        threat_id = "2147632387"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 00 00 00 40 47 66 c7 43 04 b2 d7 74 0b b8 00 00 00 80 66 c7 43 04 b1 d7 6a 00 68 80 00 00 00 51 6a 00 52 50 8d 43 48 50 e8}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 07 75 1c 6a 01 e8 ?? ?? ff ff 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 02 b3 01 8b c3 5b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {7c 6d 72 61 64 6d 69 6e 7c 00}  //weight: 1, accuracy: High
        $x_1_4 = "settellover" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQThief_E_2147632388_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQThief.E"
        threat_id = "2147632388"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 ec 2c 01 00 00 56 68 60 ea 00 00 ff 15 ?? ?? ?? ?? 6a 00 6a 02 e8 ?? ?? 00 00 8d 8d d4 fe ff ff 89 45 fc 51 50 c7 85 d4 fe ff ff 28 01 00 00 e8}  //weight: 4, accuracy: Low
        $x_1_2 = "\\injectmsg.exe" ascii //weight: 1
        $x_1_3 = "[INFO]SEND:" ascii //weight: 1
        $x_1_4 = "\\sysautorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQThief_H_2147649412_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQThief.H"
        threat_id = "2147649412"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\~@UwKJ.avi" ascii //weight: 1
        $x_1_2 = {53 65 74 57 00 00 00 00 69 6e 64 6f 77 73 48 6f 00 00 00 00 6f 6b 45 78 57}  //weight: 1, accuracy: High
        $x_1_3 = "\\Tencent\\QQ\\UserDataInfo.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQThief_I_2147649454_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQThief.I"
        threat_id = "2147649454"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\~@fatHj%d.exe" ascii //weight: 1
        $x_1_2 = {25 73 25 73 00 00 00 00 5c 65 78 70 6c 00 00 00 6f 72 65 72 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {46 41 54 33 32 2e 64 6c 6c 00 44 65 61 6c 41 00 44 65 61 6c 42}  //weight: 1, accuracy: High
        $x_1_4 = "SOFTWARE\\Tencent\\QQ\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_QQThief_K_2147678530_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQThief.K"
        threat_id = "2147678530"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQThief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s\\~@UwKJ.avi" ascii //weight: 10
        $x_10_2 = "winkb32.dll" wide //weight: 10
        $x_1_3 = "bdpass%d" ascii //weight: 1
        $x_1_4 = "passinfo%d" ascii //weight: 1
        $x_1_5 = "skypepass%d" ascii //weight: 1
        $x_1_6 = "baiduhi.exe" ascii //weight: 1
        $x_1_7 = "qq.exe" ascii //weight: 1
        $x_1_8 = "skype.exe" ascii //weight: 1
        $x_1_9 = "hdwoknqd-dwd" ascii //weight: 1
        $x_1_10 = "lrsrb-dwd" ascii //weight: 1
        $x_1_11 = "pp-dwd" ascii //weight: 1
        $x_1_12 = "rjxod-dwd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQThief_AK_2147745742_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQThief.AK!MTB"
        threat_id = "2147745742"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQThief"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setup_fat32sys" ascii //weight: 1
        $x_1_2 = "%s\\MSSETUP.DAT" ascii //weight: 1
        $x_1_3 = "%s\\WINDNSAPI.DAT" ascii //weight: 1
        $x_1_4 = "%s\\MSSYSTEM.DAT" ascii //weight: 1
        $x_1_5 = "/c move \"%s\" \"%s\" > nul" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

