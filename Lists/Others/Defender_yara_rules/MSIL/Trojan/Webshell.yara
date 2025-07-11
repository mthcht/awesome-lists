rule Trojan_MSIL_Webshell_AW_2147846437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.AW!MTB"
        threat_id = "2147846437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 05 11 05 02 6f 16 00 00 0a 6f 4c 00 00 0a 26 11 05 11 04 6f 4c 00 00 0a 26 11 05 09 6f 4c 00 00 0a 26 11 05 6f 4d 00 00 0a 26 11 04 6f 4e 00 00 0a 13 06 02 6f 16 00 00 0a 6f 4f 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_AW_2147846437_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.AW!MTB"
        threat_id = "2147846437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 9f 00 00 70 d0 24 00 00 01 28 ?? ?? ?? 0a 72 af 00 00 70 17 8d ?? ?? ?? 01 13 08 11 08 16 d0 01 00 00 1b 28 ?? ?? ?? 0a a2 11 08 28 ?? ?? ?? 0a 14 17 8d ?? ?? ?? 01 13 09 11 09 16 09 a2 11 09}  //weight: 2, accuracy: Low
        $x_1_2 = "__Render__control1" ascii //weight: 1
        $x_1_3 = "payload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_AB_2147850013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.AB!MTB"
        threat_id = "2147850013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 1c 00 00 0a 28 14 00 00 0a 07 6f 16 00 00 0a 28 14 00 00 0a 07 6f 16 00 00 0a 6f 2d 00 00 0a 11 06 16 11 06 8e 69 6f 1e 00 00 0a 28 2e 00 00 0a 6f 2c 00 00 0a 02 6f 0a 00 00 0a 6f 2a 00 00 0a 08 1f 10 6f 2f 00 00 0a 6f 2c 00 00 0a de 03 26}  //weight: 5, accuracy: High
        $x_5_2 = {28 10 00 00 0a 28 10 00 00 0a 28 10 00 00 0a 72 ?? ?? ?? ?? 28 11 00 00 0a 6f 12 00 00 0a 28 11 00 00 0a 6f 12 00 00 0a 28 11 00 00 0a 6f 12 00 00 0a 0a 72 ?? ?? ?? ?? 0b 73 13 00 00 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_RPZ_2147888263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.RPZ!MTB"
        threat_id = "2147888263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IIsWebVirtualDir" wide //weight: 1
        $x_1_2 = "IIS://localhost/W3SVC" wide //weight: 1
        $x_1_3 = "Process Kill Success" wide //weight: 1
        $x_1_4 = "r00ts Team WebShell" wide //weight: 1
        $x_1_5 = "Hello! Hack.  By Faker" wide //weight: 1
        $x_1_6 = "Bin_Button_KillMe" wide //weight: 1
        $x_1_7 = "Add xp_cmdshell" wide //weight: 1
        $x_1_8 = "tools/download.ashx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_RPX_2147888806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.RPX!MTB"
        threat_id = "2147888806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3g/bottom.ascx" wide //weight: 1
        $x_1_2 = "3g/solutitop.aspx" wide //weight: 1
        $x_1_3 = "OGVlYjU4NDEzMjYzMQ==" wide //weight: 1
        $x_1_4 = "www.gov.cn" wide //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Encoding" ascii //weight: 1
        $x_1_7 = "Convert" ascii //weight: 1
        $x_1_8 = "Concat" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_MBER_2147895850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.MBER!MTB"
        threat_id = "2147895850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "61"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 28 0c 00 00 0a 20 80 c3 c9 01 6f 0d 00 00 0a}  //weight: 10, accuracy: High
        $x_10_2 = "qifwqdrbsarz" ascii //weight: 10
        $x_10_3 = {41 70 70 5f 57 65 62 5f [0-22] 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_10_4 = {02 6f 14 00 00 0a 72 37 00 00 70 72 3b 00 00 70 6f 15 00 00 0a 00 28 16 00 00 0a 02 6f}  //weight: 10, accuracy: High
        $x_10_5 = "FrameworkInitialize" ascii //weight: 10
        $x_10_6 = "CreateDecryptor" ascii //weight: 10
        $x_1_7 = {35 7e 00 2f 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 2f 00 71 00 69 00 66 00 77 00 71 00 64 00 72 00 62 00 73 00 61 00 72 00 7a 00 2e 00 61 00 73 00 70 00 78 00 00 03 6b 00 00 21 38 00 65 00 64 00 62 00 32 00 33 00 31 00 36 00 30 00 64 00 31 00 35 00 37 00 31 00 61 00 30 00 00 03 55 00 00 35 7e 00 2f 00 43}  //weight: 1, accuracy: High
        $x_1_8 = {7e 00 2f 00 43 00 6f 00 6d 00 6d 00 6f 00 6e 00 2f 00 69 00 61 00 62 00 78 00 65 00 64 00 74 00 6c 00 74 00 74 00 65 00 78 00 2e 00 61 00 73 00 70 00 78 00 00 03 6b 00 00 21 38 00 65 00 64 00 62 00 32 00 33 00 31 00 36 00 30 00 64 00 31 00 35 00 37 00 31 00 61 00 30 00 00 03 55 00 00 35 7e 00 2f 00 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Webshell_AMAF_2147900795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.AMAF!MTB"
        threat_id = "2147900795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 16 9a 74 ?? 00 00 01 fe ?? ?? ?? 25 17 9a 74 ?? 00 00 01 fe ?? ?? ?? 25 19 9a 17 28 ?? 00 00 0a 0b 26 28 ?? 00 00 0a 26 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_SPDO_2147908218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.SPDO!MTB"
        threat_id = "2147908218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 17 8d 50 00 00 01 0d 09 16 1f 2c 9d 09 6f ?? ?? ?? 0a 0a 16 0b 2b 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_VG_2147922486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.VG!MTB"
        threat_id = "2147922486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DownLoadPage.aspx" wide //weight: 1
        $x_1_2 = "ShowSQL.aspx" wide //weight: 1
        $x_1_3 = "ShowLog.aspx" wide //weight: 1
        $x_1_4 = "Index.aspx" wide //weight: 1
        $x_1_5 = "CallPage.aspx" wide //weight: 1
        $x_1_6 = "payloadStoreName" wide //weight: 1
        $x_1_7 = "d0079d9c035490ee" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_GV_2147922487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.GV!MTB"
        threat_id = "2147922487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "App_global.asax.pzw_bvxi" ascii //weight: 1
        $x_1_2 = "Create_ASP_async_aspx" ascii //weight: 1
        $x_4_3 = "3c6e0b8a9c15224a" wide //weight: 4
        $x_4_4 = "{payloadStoreName}" wide //weight: 4
        $x_1_5 = "SSO.aspx" wide //weight: 1
        $x_1_6 = "API.aspx" wide //weight: 1
        $x_1_7 = "async.aspx" wide //weight: 1
        $x_1_8 = "Login.aspx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Webshell_AMI_2147922623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.AMI!MTB"
        threat_id = "2147922623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 08 08 6f ?? 00 00 0a 07 16 02 6f 0e 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 02 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_MBWA_2147926109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.MBWA!MTB"
        threat_id = "2147926109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6c 00 6f 00 61 00 64 00 39 00 36 00 51 00 4a 00 00 09 4c 00 6f 00 61 00 64 00 00 05 4c 00 59}  //weight: 2, accuracy: High
        $x_1_2 = "202cb962ac59075b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_EAAU_2147929830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.EAAU!MTB"
        threat_id = "2147929830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 11 0b 11 0c 11 0d 6f 92 00 00 0a 6f 23 00 00 0a 72 19 16 00 70 28 24 00 00 0a 6f 93 00 00 0a 26 00 11 0d 17 58 13 0d 11 0d 11 0c 6f 94 00 00 0a fe 04 13 10 11 10 2d c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_MBS_2147934926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.MBS!MTB"
        threat_id = "2147934926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 a0 03 00 00 95 5f 7e 36 00 00 04 20 f2 01 00 00 95 61 58 81 07 00 00 01 11 28 18 95 7e 36 00 00 04 1f 67}  //weight: 1, accuracy: High
        $x_1_2 = {17 59 11 20 20 72 06 00 00 95 5f 11 20 20 9e 0d 00 00 95 61 58 80 1b 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Webshell_MBT_2147934981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.MBT!MTB"
        threat_id = "2147934981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 59 11 20 20 30 0e 00 00 95 5f 11 20 20 ef 05 00 00 95 61 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_AWB_2147944502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.AWB!MTB"
        threat_id = "2147944502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 04 00 02 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 16 fe 01 13 10 11 10 3a ?? ?? ?? ?? 00 09 17 58 0d 07 ?? ?? ?? 00 70 11 04 6f ?? 00 00 0a 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "Directory delete new success" wide //weight: 1
        $x_1_3 = "Directory Renamed Success" wide //weight: 1
        $x_1_4 = "File Renamed Success" wide //weight: 1
        $x_1_5 = "File Copy Success" wide //weight: 1
        $x_1_6 = "Directory created success" wide //weight: 1
        $x_1_7 = "File Delete Success" wide //weight: 1
        $x_1_8 = "Process Kill Success" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Webshell_GVA_2147946063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Webshell.GVA!MTB"
        threat_id = "2147946063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Webshell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "txtNewPasswordConfirmed" ascii //weight: 3
        $x_3_2 = "lnkForgotPassword" ascii //weight: 3
        $x_3_3 = "lnkForgotPassword_Click" ascii //weight: 3
        $x_3_4 = "chkAutoLogin" ascii //weight: 3
        $x_1_5 = "~/frmResetURL.aspx" wide //weight: 1
        $x_1_6 = "~/MasterPages/Dummy.Master" wide //weight: 1
        $x_1_7 = "~/frmForgotPassword.aspx" wide //weight: 1
        $x_1_8 = "@EmailAddress" wide //weight: 1
        $x_2_9 = "imgCaptcha" wide //weight: 2
        $x_2_10 = "CaptchaImage" wide //weight: 2
        $x_1_11 = "txtCaptcha" wide //weight: 1
        $x_1_12 = "~/CompileSite.aspx" wide //weight: 1
        $x_1_13 = "~/LoginPreview.aspx" wide //weight: 1
        $x_1_14 = "grenhy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

