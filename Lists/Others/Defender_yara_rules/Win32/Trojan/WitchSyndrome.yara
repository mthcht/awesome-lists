rule Trojan_Win32_WitchSyndrome_A_2147904797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WitchSyndrome.A!dha"
        threat_id = "2147904797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WitchSyndrome"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "%RGEsftr23$%23%EWFWQ@!#$@!$@#%ERFGSAD@#$15346rggweqer13234" ascii //weight: 20
        $x_20_2 = "Rj8jZVwFVA==" ascii //weight: 20
        $x_20_3 = "UjspKBQLAAEISE1IQlZXNjgoNiUpTk1oJVdBLB5MKCIjNSAuKiFXQUwUb2gYLhUIGBEtBhtcRQA=" ascii //weight: 20
        $x_20_4 = "cjspdkE5JABdUEFWQQ==" ascii //weight: 20
        $x_20_5 = "!!@Supper@!!" ascii //weight: 20
        $x_20_6 = "LsDomainsAndPCs" ascii //weight: 20
        $x_4_7 = "SECURITY_IMPERSONATION_LEVEL" ascii //weight: 4
        $x_4_8 = "SHARE_INFO_2" ascii //weight: 4
        $x_4_9 = "WTS_CONNECTSTATE_CLASS" ascii //weight: 4
        $x_4_10 = "WTS_SESSION_INFO" ascii //weight: 4
        $x_4_11 = "LOGON32_PROVIDER_DEFAULT" ascii //weight: 4
        $x_4_12 = "LOGON32_LOGON_INTERACTIVE" ascii //weight: 4
        $x_4_13 = "WTSGetActiveConsoleSessionId" ascii //weight: 4
        $x_4_14 = "WTSEnumerateSessions" ascii //weight: 4
        $x_4_15 = "DuplicateTokenHandle" ascii //weight: 4
        $x_4_16 = "GetSessionUserToken" ascii //weight: 4
        $x_4_17 = "WTS_CURRENT_SERVER_HANDLE" ascii //weight: 4
        $x_4_18 = "Execwmr" ascii //weight: 4
        $x_4_19 = "WinNT://" ascii //weight: 4
        $x_4_20 = "get_AllKeys" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 10 of ($x_4_*))) or
            ((2 of ($x_20_*) and 5 of ($x_4_*))) or
            ((3 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_WitchSyndrome_B_2147904798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WitchSyndrome.B!dha"
        threat_id = "2147904798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WitchSyndrome"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "PSDSderdfccew4rtfgdverTERY&%^UHFdvcawe4@TRRUTYUJGFBVXCWQRWerterYrerewrwer!24" ascii //weight: 1
        $x_1_2 = "YiUpOgc5BgsJET9LK2hTCQMTBRgKASYgIjRPGDIwPiMoGAwIAwRaLycgNyU5MC5wNDIvMTUtPiY=" ascii //weight: 1
        $x_1_3 = "IyAhMAsXIjtUUA0MIA==" ascii //weight: 1
        $x_1_4 = "cDBrcwAIEQ==" ascii //weight: 1
        $x_1_5 = "NSshfQAoEQ==" ascii //weight: 1
        $x_1_6 = {3c 00 61 00 20 00 68 00 72 00 65 00 66 00 3d 00 27 00 23 00 27 00 ?? 6f 00 6e 00 63 00 6c 00 69 00 63 00 6b 00 3d 00 22 00 22 00 66 00 70 00 6f 00 73 00 74 00 28 00 27 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3c 61 20 68 72 65 66 3d 27 23 27 ?? 6f 6e 63 6c 69 63 6b 3d 22 22 66 70 6f 73 74 28 27}  //weight: 1, accuracy: Low
        $x_1_8 = {3c 00 62 00 72 00 3e 00 3c 00 69 00 6e 00 70 00 75 00 74 00 ?? 74 00 79 00 70 00 65 00 3d 00 22 00 22 00 68 00 69 00 64 00 64 00 65 00 6e 00 22 00}  //weight: 1, accuracy: Low
        $x_1_9 = {3c 62 72 3e 3c 69 6e 70 75 74 ?? 74 79 70 65 3d 22 22 68 69 64 64 65 6e 22}  //weight: 1, accuracy: Low
        $x_1_10 = "cppath" ascii //weight: 1
        $x_1_11 = "<tr><td>{0}</td><td>&lt;DIR&gt;<td>{1}</td><td></td><td></td><td>{2}</td></tr>" ascii //weight: 1
        $x_1_12 = "onclick=\"\"fget" ascii //weight: 1
        $x_1_13 = "onclick=\"\"fcopy" ascii //weight: 1
        $x_1_14 = "onclick=\"\"fdel" ascii //weight: 1
        $x_1_15 = "txtCMP" ascii //weight: 1
        $x_1_16 = "txtCMPHidden" ascii //weight: 1
        $x_1_17 = "lblDrives" ascii //weight: 1
        $x_1_18 = "lblPath" ascii //weight: 1
        $x_1_19 = "lblDirOut" ascii //weight: 1
        $x_1_20 = "resWm" ascii //weight: 1
        $x_1_21 = "btnWm" ascii //weight: 1
        $x_1_22 = "txtSleep" ascii //weight: 1
        $x_1_23 = "btnEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Trojan_Win32_WitchSyndrome_C_2147904799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WitchSyndrome.C!dha"
        threat_id = "2147904799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WitchSyndrome"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CRRFERWERQWEARFASFDSADRTRWEFSDFdfsa454354356tfdsgdszgfsd!32435c" ascii //weight: 1
        $x_1_2 = "Sec-Fetch-ATH" ascii //weight: 1
        $x_1_3 = "EF454tf@33254yc3#" ascii //weight: 1
        $x_1_4 = "Sec-Fetch-CN" ascii //weight: 1
        $x_1_5 = "Sec-Fetch-SQ" ascii //weight: 1
        $x_1_6 = "SqlDataReader" ascii //weight: 1
        $x_1_7 = "SqlCommand" ascii //weight: 1
        $x_1_8 = "set_ConnectionString" ascii //weight: 1
        $x_1_9 = "System.Data.SqlClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

