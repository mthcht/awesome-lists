rule PWS_Win32_QQRob_T_2147565093_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQRob.T"
        threat_id = "2147565093"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQRob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "237"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "QQRob" ascii //weight: 100
        $x_100_2 = "wpa.qq.com/msgrd?V" ascii //weight: 100
        $x_5_3 = "HELO" ascii //weight: 5
        $x_5_4 = "AUTH LOGIN" ascii //weight: 5
        $x_5_5 = "MAIL FROM:" ascii //weight: 5
        $x_5_6 = "RCPT TO:" ascii //weight: 5
        $x_5_7 = ":try" ascii //weight: 5
        $x_5_8 = "if exist \"" ascii //weight: 5
        $x_5_9 = "goto try" ascii //weight: 5
        $x_1_10 = "RAV.EXE" ascii //weight: 1
        $x_1_11 = "RAVMON.EXE" ascii //weight: 1
        $x_1_12 = "RAVTIMER.EXE" ascii //weight: 1
        $x_1_13 = "KAVPFW.EXE" ascii //weight: 1
        $x_1_14 = "KVFW.EXE" ascii //weight: 1
        $x_1_15 = "KAVPLUS.EXE" ascii //weight: 1
        $x_1_16 = "KWATCHUI.EXE" ascii //weight: 1
        $x_1_17 = "KPOPMON.EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 6 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_100_*) and 7 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQRob_2147566949_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQRob"
        threat_id = "2147566949"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQRob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "QQRobber" ascii //weight: 3
        $x_2_2 = "VCMpX?dkGsYsYnu_VRMqGbuaY>y]Xs<kUsIiGralGbAoX<" ascii //weight: 2
        $x_2_3 = {61 6c 61 32 71 71 00}  //weight: 2, accuracy: High
        $x_2_4 = "FD81FABA512C494448F1E4AA647C611B" ascii //weight: 2
        $x_2_5 = "<a href=\"ip.php?" ascii //weight: 2
        $x_1_6 = "NTdhcp.exe" ascii //weight: 1
        $x_1_7 = "MAIL FROM: <" ascii //weight: 1
        $x_1_8 = "RCPT TO: <" ascii //weight: 1
        $x_1_9 = "CallNextHookEx" ascii //weight: 1
        $x_1_10 = "\\Explorer\\ShellExecuteHooks" ascii //weight: 1
        $x_1_11 = "\\Recovery Genius 21st" ascii //weight: 1
        $x_1_12 = "application/x-www-form-" ascii //weight: 1
        $x_1_13 = "Personal FireWall" ascii //weight: 1
        $x_1_14 = "rising\\Rav" ascii //weight: 1
        $x_1_15 = "Tencent\\QQ" ascii //weight: 1
        $x_1_16 = "JumpHookOn" ascii //weight: 1
        $x_1_17 = ".qq.com/clienturl_simp_19" ascii //weight: 1
        $x_1_18 = ".qq.com/cgi-bin/after_logon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_QQRob_W_2147625116_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/QQRob.W"
        threat_id = "2147625116"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "QQRob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 02 6a 00 6a fc 57 e8 ?? ?? ?? ff 6a 00 8d 45 f0 50 6a 04 53 57 e8 ?? ?? ?? ff 81 33 7d a0 86 59 6a 00 57 e8 ?? ?? ?? ff 3b 03 0f 86 ?? ?? 00 00 6a 02 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 6a 00 6a fc 57 e8 ?? ?? ?? ff 6a 00 8d 45 f0 50 6a 04 53 57 e8 ?? ?? ?? ff 81 33 ?? ?? ?? ?? 6a 00 57 e8 ?? ?? ?? ff 3b 03 0f 86 ?? ?? 00 00 6a 02 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

