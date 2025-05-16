rule Backdoor_MSIL_Remcos_2147744692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos!MTB"
        threat_id = "2147744692"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_kbHook" ascii //weight: 1
        $x_1_2 = "get_User" ascii //weight: 1
        $x_1_3 = "get_Password" ascii //weight: 1
        $x_1_4 = "get_TotalPhysicalMemory" ascii //weight: 1
        $x_1_5 = "get_ProcessName" ascii //weight: 1
        $x_1_6 = "get_Attachments" ascii //weight: 1
        $x_1_7 = "get_CtrlKeyDown" ascii //weight: 1
        $x_1_8 = "get_AltKeyDown" ascii //weight: 1
        $x_1_9 = "get_CapsLock" ascii //weight: 1
        $x_1_10 = "get_ShiftKeyDown" ascii //weight: 1
        $x_1_11 = "set_kbHook" ascii //weight: 1
        $x_1_12 = "set_Credentials" ascii //weight: 1
        $x_1_13 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_14 = "set_UseShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_VA_2147771870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.VA!MTB"
        threat_id = "2147771870"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "remove_LinkClicked" ascii //weight: 1
        $x_1_2 = "ll_Search_LinkClicked" ascii //weight: 1
        $x_1_3 = "ll_Email_LinkClicked" ascii //weight: 1
        $x_1_4 = "ll_Calculator_LinkClicked" ascii //weight: 1
        $x_1_5 = "ll_AddRecords_LinkClicked" ascii //weight: 1
        $x_1_6 = "ll_Print_LinkClicked" ascii //weight: 1
        $x_1_7 = "ll_Export_LinkClicked" ascii //weight: 1
        $x_1_8 = "StrReverse" ascii //weight: 1
        $x_1_9 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_10 = "DebuggerStepThroughAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_12 = "set_PasswordChar" ascii //weight: 1
        $x_1_13 = "get_KeyChar" ascii //weight: 1
        $x_1_14 = "get_DataMember" ascii //weight: 1
        $x_1_15 = "OleDbDataReader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_VPA_2147771953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.VPA!MTB"
        threat_id = "2147771953"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$346dba90-52eb-4e4f-a899-07778c14f8f2" ascii //weight: 1
        $x_1_2 = "nVirtKey" ascii //weight: 1
        $x_1_3 = "C:\\Users\\Ceceilia\\Documents" wide //weight: 1
        $x_1_4 = "YFSWIbi8Sjyx+0VlA0uUwvPTsc6z0wl6ze1xLmzgCdNXZBRCDlUpLDwCcIQntYxRqN9595+YZdtj68ZX0O" ascii //weight: 1
        $x_1_5 = "fFYU5HFs5MQ5U2ZPmjB3YlXdlAmTqyZMnji3akrt3JqqORNPqR0fHR+dPWUy0IOgqLa2uob+YTJfWs" ascii //weight: 1
        $x_1_6 = "2o8IPervB45+ChYN7CFgSM9pb18YSyRFWBeP80iPniOjmD3zxIv8n3gU" ascii //weight: 1
        $x_1_7 = "rlMsfgLgqPg8jOX4+D00N8ONK6FjAf80UCFRsnmCraUNaOuZ0vw1sAWsTPRb0A9V" ascii //weight: 1
        $x_1_8 = "4U83n948NinYE" ascii //weight: 1
        $x_1_9 = "cQaF7sf8WQT" ascii //weight: 1
        $x_1_10 = "BqoiAsE6CtTOEHizJzuXfc9Ov62jWMozGAM1gPMaywEuhJ57d" ascii //weight: 1
        $x_1_11 = "McCCmjKAisB+PoTrLSS49T0" ascii //weight: 1
        $x_1_12 = "ZvA1vHMaSiXx2zgdOBfHPhZlpErDx8w1sn37wa3MY6Xf05DTqP07TcHJYNMjOjoPIrOYfpEfZq+QJ+uz9Sj+iy9RqdPYbwD5q5ASWN2" ascii //weight: 1
        $x_1_13 = "KsGlflCzyTIVOF8ZTl+EvS0D6BqIbKaJaB5OeRRzVox1i71Gsa8BcBZz2cQV52U9WK" ascii //weight: 1
        $x_1_14 = "9ayN0d+vHA+z2S4UG5TW8EJ" ascii //weight: 1
        $x_1_15 = "HqActY7QTCv6HVyH5" ascii //weight: 1
        $x_1_16 = "VJj778IFoXyfUSktY8v8l" ascii //weight: 1
        $x_1_17 = "SvMELtvFmJ8CtAtyzR4l" ascii //weight: 1
        $x_1_18 = "xPJdBKX6dFzjpXsieQ6lc+rA1aG87IONHSD839l7v+aZ6bI1mtm" ascii //weight: 1
        $x_1_19 = "DU+ZFHAAOAAA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_VPL_2147771954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.VPL!MTB"
        threat_id = "2147771954"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$162a245c-1727-4b4e-ab62-d7277af5a723" ascii //weight: 1
        $x_1_2 = "ServerName\\serverName.txt" wide //weight: 1
        $x_1_3 = "Nursery_Management_System.signIn.resources" ascii //weight: 1
        $x_1_4 = "Nursery_Management_System.sign.resources" ascii //weight: 1
        $x_1_5 = "Nursery_Management_System.signUp.resources" ascii //weight: 1
        $x_1_6 = "Nursery_Management_System.Analytics.resources" ascii //weight: 1
        $x_1_7 = "Nursery_Management_System.Properties.Resources.resources" ascii //weight: 1
        $x_1_8 = "Nursery_Management_System.childDailyDetails.resources" ascii //weight: 1
        $x_1_9 = "Nursery_Management_System.adminPendingRequests.resources" ascii //weight: 1
        $x_1_10 = "LinkLabelLinkClickedEventArgs" ascii //weight: 1
        $x_1_11 = "get_MNBVCXCZBGYH" ascii //weight: 1
        $x_1_12 = "op_Equality" ascii //weight: 1
        $x_1_13 = "op_Inequality" ascii //weight: 1
        $x_1_14 = "WrapNonExceptionThrows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_VAP_2147772354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.VAP!MTB"
        threat_id = "2147772354"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IPHostEntry" ascii //weight: 1
        $x_1_2 = "GetHostEntry" ascii //weight: 1
        $x_1_3 = "op_Equality" ascii //weight: 1
        $x_1_4 = "op_Inequality" ascii //weight: 1
        $x_1_5 = "SQUARE CAPITAL LIMITED" ascii //weight: 1
        $x_1_6 = "$811d2047-d9c1-4f8e-8535-0bdc5955dc3f" ascii //weight: 1
        $x_1_7 = "conf/Server.xml" wide //weight: 1
        $x_1_8 = "Username" wide //weight: 1
        $x_1_9 = "PuppetMasterIP" wide //weight: 1
        $x_1_10 = "PuppetMasterPort" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_MA_2147808215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.MA!MTB"
        threat_id = "2147808215"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 16 06 8e 69 28 ?? ?? ?? 0a 06 0b dd 03 00 00 00 26 de db}  //weight: 10, accuracy: Low
        $x_2_2 = "://brianetaveras.byethost13.com" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_MA_2147808215_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.MA!MTB"
        threat_id = "2147808215"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www.uplooder.net" wide //weight: 1
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "wener/ gifnocpi" wide //weight: 1
        $x_1_4 = "esaeler/ gifnocpi" wide //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "Test-Connection www.google.com" wide //weight: 1
        $x_1_7 = "user:password" wide //weight: 1
        $x_1_8 = "get_GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ZSA_2147809040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ZSA!MTB"
        threat_id = "2147809040"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "edbb2e09-680c-4f47-b7c7-15a6595f9aeb" ascii //weight: 10
        $x_1_2 = "Equals" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "GetFrame" ascii //weight: 1
        $x_1_5 = "ComputeHash" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "TransformFinalBlock" ascii //weight: 1
        $x_1_8 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_9 = "GetCallingAssembly" ascii //weight: 1
        $x_1_10 = "Append" ascii //weight: 1
        $x_1_11 = "ToString" ascii //weight: 1
        $x_1_12 = "GetName" ascii //weight: 1
        $x_1_13 = "Mode" ascii //weight: 1
        $x_1_14 = "Padding" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ABZ_2147827397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ABZ!MTB"
        threat_id = "2147827397"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 16 73 06 ?? ?? 0a 73 07 ?? ?? 0a 0d 00 09 08 6f 08 ?? ?? 0a 00 00 de 0b 09 2c 07 09 6f 09 ?? ?? 0a 00 dc 08 6f 0a ?? ?? 0a 13 04 de 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ABV_2147828762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ABV!MTB"
        threat_id = "2147828762"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {77 17 a2 09 09 03 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 38 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "QWKDOWQKDOQKOD" ascii //weight: 1
        $x_1_3 = "GetFolderPath" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_GJW_2147835062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.GJW!MTB"
        threat_id = "2147835062"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 38 07 09 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 13 04 07 6f ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 de 24 08 2b cc 06 2b cb 6f ?? ?? ?? 0a 2b c6 0d 2b c5}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SPQT_2147838121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SPQT!MTB"
        threat_id = "2147838121"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 05 11 06 9a 0c 08 6f ?? ?? ?? 0a 72 01 00 00 70 28 ?? ?? ?? 0a 2c 09 06 08 6f ?? ?? ?? 0a 2b 0e 11 06 17 58 13 06 11 06 11 05 8e 69 32 d1}  //weight: 6, accuracy: Low
        $x_1_2 = "kedaiorangmelayu.xyz/loader/uploads/withoutstartup_Mygnhcvd.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_MB_2147842271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.MB!MTB"
        threat_id = "2147842271"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 04 18 5b 07 11 04 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 11 04 18 58 13 04 11 04 08 32 df 09 13 05 de 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SPJ_2147843939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SPJ!MTB"
        threat_id = "2147843939"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aktelle_Downloads" ascii //weight: 1
        $x_1_2 = "Aktuelle_Sammlung" ascii //weight: 1
        $x_1_3 = "_klammern_ignorieren" ascii //weight: 1
        $x_1_4 = "_Header_dllink" ascii //weight: 1
        $x_1_5 = "_donotcleanup" ascii //weight: 1
        $x_1_6 = "ch_samprate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_GNC_2147850667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.GNC!MTB"
        threat_id = "2147850667"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c710769741772cfe14ccee264b97100ae" ascii //weight: 1
        $x_1_2 = "cc4afb70d0ebbaa3d490d0ec1da16b30c" ascii //weight: 1
        $x_1_3 = "QkhISEc2NiU=" ascii //weight: 1
        $x_1_4 = "QkhISEc2NiQ=" ascii //weight: 1
        $x_1_5 = "BHHHG66" ascii //weight: 1
        $x_1_6 = "Documents\\CryptoObfuscator_Output\\BHHHG66.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAE_2147890147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAE!MTB"
        threat_id = "2147890147"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 08 11 06 08 8e 69 5d 08 11 06 08 8e 69 5d 91 09 11 06 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 08 11 06 17 58 08 8e 69 5d 91 28 ?? 00 00 0a 59 20 ?? ?? 00 00 58 20 ?? ?? 00 00 5d d2 9c 00 11 06 15 58 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d ac}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AATF_2147893355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AATF!MTB"
        threat_id = "2147893355"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 05 03 02 8e 69 6f ?? 00 00 0a 0a 06 28 ?? 00 00 0a 00 06 0b 2b 00 07 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "##C##r#e##a#t##e##I##n#s#t##a##n#c##e##" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SK_2147893559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SK!MTB"
        threat_id = "2147893559"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 73 01 00 00 0a 72 01 00 00 70 28 ?? ?? ?? 0a 0a 06 16 06 8e 69 28 ?? ?? ?? 0a 06 0b dd 03 00 00 00 26 de db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SK_2147893559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SK!MTB"
        threat_id = "2147893559"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 17 59 13 06 2b 17 00 28 ?? ?? ?? 06 07 11 06 9a 6f ?? ?? ?? 06 00 00 11 06 17 59 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AAUI_2147894389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AAUI!MTB"
        threat_id = "2147894389"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 7e ?? 00 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 03 08 20 8e 10 00 00 58 20 8d 10 00 00 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 aa}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAF_2147896274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAF!MTB"
        threat_id = "2147896274"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 24 1d 11 0a 5f 91 13 18 11 18 19 62 11 18 1b 63 60 d2 13 18 11 05 11 0a 11 05 11 0a 91 11 18 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 08 32 d1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAG_2147896398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAG!MTB"
        threat_id = "2147896398"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 11 04 07 8e 69 5d 13 08 11 04 08 6f ?? 00 00 0a 5d 13 09 07 11 08 91 13 0a 08 11 09 6f ?? 00 00 0a 13 0b 02 07 11 04 28 ?? 00 00 06 13 0c 02 11 0a 11 0b 11 0c 28 ?? 00 00 06 13 0d 07 11 08 02 11 0d 28 ?? 00 00 06 9c 00 11 04 17 59 13 04 11 04 16 fe 04 16 fe 01 13 0e 11 0e 2d a2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AAXV_2147897624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AAXV!MTB"
        threat_id = "2147897624"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 8e 69 5d 18 58 1b 58 1d 59 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 28 ?? 00 00 0a 04 08 20 89 10 00 00 58 20 88 10 00 00 59 04 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 1b 2c 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AAYL_2147898309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AAYL!MTB"
        threat_id = "2147898309"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 8e 69 5d 18 58 1b 58 1d 59 04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 28 ?? ?? 00 0a 04 08 20 89 10 00 00 58 20 88 10 00 00 59 04 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 1b 2c 89 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AAYR_2147898455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AAYR!MTB"
        threat_id = "2147898455"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0b 72 31 00 00 70 28 ?? 00 00 06 72 63 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 13 01}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AAYU_2147898586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AAYU!MTB"
        threat_id = "2147898586"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 05 03 02 8e 69 6f ?? 01 00 0a 0a 06 28 ?? 01 00 0a 00 06 0b 2b 00 07 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "vsLhLhJBUCivwMwEUMTxEBAvTCUQJhvCDywZrpUfhf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SM_2147898759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SM!MTB"
        threat_id = "2147898759"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 0a 8f 11 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 2, accuracy: High
        $x_2_2 = "WNHBNMKL.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SM_2147898759_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SM!MTB"
        threat_id = "2147898759"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 11 11 08 17 58 13 17 11 08 11 0e 5d 13 12 11 17 11 0e 5d 13 18 11 0d 11 18 91 11 11 58 13 19 11 0d 11 12 91 13 1a 11 1a 11 13 11 08 1f 16 5d 91 61 13 1b 11 1b 11 19 59 13 1c 11 0d 11 12 11 1c 11 11 5d d2 9c 11 08 17 58 13 08 11 08 11 0e 11 14 17 58 5a fe 04 13 1d 11 1d 2d 9e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SL_2147899870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SL!MTB"
        threat_id = "2147899870"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 6f 0f 00 00 0a 13 04 06 07 11 04 03 58 d1 9d 07 17 58 0b 09 17 58 0d 09 08 6f 0e 00 00 0a 32 de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ABAA_2147900103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ABAA!MTB"
        threat_id = "2147900103"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 8e 69 17 59 0d 2b 0e 07 08 06 09 91 9c 08 17 58 0c 09 17 59 0d 09 16 2f ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AGAA_2147900229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AGAA!MTB"
        threat_id = "2147900229"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 07 1f 0f 1f 10 28 ?? ?? 00 06 7e ?? 00 00 04 06 07 28 ?? ?? 00 06 7e ?? 00 00 04 06 18 28 ?? ?? 00 06 7e ?? 00 00 04 06 1b 28 ?? ?? 00 06 7e ?? 00 00 04 06 28 ?? ?? 00 06 0d 7e ?? 00 00 04 09 04 16 04 8e 69 28 ?? ?? 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ZM_2147901412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ZM!MTB"
        threat_id = "2147901412"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 00 2b 35 16 2b 35 2b 3a 2b 3f 00 2b 0b 2b 0c 6f ?? ?? ?? 0a 00 00 de 14 08 2b f2 07 2b f1 08 2c 0a 16 2d 06 08 6f ?? ?? ?? 0a 00 dc 07 6f ?? ?? ?? 0a 0d 16 2d cb de 30 06 2b c8 73 ?? ?? ?? 0a 2b c4 73 ?? ?? ?? 0a 2b bf 0c 2b be}  //weight: 1, accuracy: Low
        $x_1_2 = "EnumProcessModules" ascii //weight: 1
        $x_1_3 = "OpenProcess" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ARA_2147901545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ARA!MTB"
        threat_id = "2147901545"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 08 02 8e 69 5d 18 58 1f 0a 58 1f 0c 59 7e ?? ?? ?? 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1f 0b 58 1f 0d 59 91 61 28 ?? ?? ?? 06 02 08 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 59 02 8e 69 5d 91 59 20 ?? ?? ?? 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 9a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_DGAA_2147902218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.DGAA!MTB"
        threat_id = "2147902218"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 1a 8d 18 00 00 01 25 16 11 04 a2 25 17 7e 16 00 00 0a a2 25 18 07 a2 25 19 17 8c 04 00 00 01 a2 13 06 11 05 08 6f ?? 00 00 0a 09 20 00 01 00 00 14 14 11 06 74 01 00 00 1b 6f ?? 00 00 0a 26 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_DXAA_2147902628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.DXAA!MTB"
        threat_id = "2147902628"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 13 06 11 05 13 07 11 06 11 07 11 06 11 07 6f ?? 00 00 0a 06 11 05 06 8e 69 5d 91 61 d2 6f ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 03 6f ?? 00 00 0a fe 04 13 08 11 08 2d c4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_EMAA_2147902974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.EMAA!MTB"
        threat_id = "2147902974"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 2b 1e 02 11 04 9a 28 ?? 00 00 0a 1f 14 da 13 05 08 11 05 b4 6f ?? 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ETAA_2147903181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ETAA!MTB"
        threat_id = "2147903181"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8e 69 5d 91 07 08 07 8e 69 5d 18 58 1f 0b 58 1f 0d 59 91 61 28}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SQ_2147905071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SQ!MTB"
        threat_id = "2147905071"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 11 00 00 0a 72 d7 00 00 70 28 12 00 00 0a 13 04 11 04 28 13 00 00 0a dd 06 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_IYAA_2147906746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.IYAA!MTB"
        threat_id = "2147906746"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 ?? 08 20 0e 02 00 00 58 20 0d 02 00 00 59 1b 59 1b 58 ?? 8e 69 5d 1f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SS_2147906976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SS!MTB"
        threat_id = "2147906976"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 17 58 13 04 07 11 04 07 8e 69 5d 91 13 05 08 09 1f 16 5d 91 13 06 07 09 91 11 06 61 13 07 07 09 11 07 11 05 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 07 8e 69 32 c2}  //weight: 2, accuracy: High
        $x_2_2 = "MeshViewer.MeshViewer.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ST_2147908194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ST!MTB"
        threat_id = "2147908194"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 08 17 58 13 06 07 08 07 08 91 28 ?? ?? ?? 06 08 1f 16 5d 91 61 07 11 06 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 08 17 58 0c 00 08 09 fe 04 13 07 11 07 2d ca}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SU_2147908942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SU!MTB"
        threat_id = "2147908942"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NotThere.Properties.Resources.resources" ascii //weight: 2
        $x_2_2 = "$37cec485-00a6-4f47-9035-15ca486959d8" ascii //weight: 2
        $x_2_3 = "https://github.com/Saad888/AutoSynthesis/issues" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SV_2147908943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SV!MTB"
        threat_id = "2147908943"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$810a9e58-bd80-4bea-b844-31e4e2921fc3" ascii //weight: 2
        $x_2_2 = "MagicBar.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SR_2147909347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SR!MTB"
        threat_id = "2147909347"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 04 00 00 0a 72 01 00 00 70 28 05 00 00 0a 0b 07 8e 69 20 00 04 00 00 2e e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAP_2147911960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAP!MTB"
        threat_id = "2147911960"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAS_2147914815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAS!MTB"
        threat_id = "2147914815"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 18 58 18 59 91 61 03 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAV_2147916030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAV!MTB"
        threat_id = "2147916030"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 13 ?? 11 ?? 11 ?? 91 11 ?? 61 13 ?? 11 ?? 17 58 11 ?? 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAX_2147916495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAX!MTB"
        threat_id = "2147916495"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 58 08 5d 13 ?? 06 7b ?? 00 00 04 11 ?? 91 11 ?? 61 11 ?? 59 20 00 02 00 00 58 13 ?? 11 ?? 20 00 01 00 00 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SDAA_2147916576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SDAA!MTB"
        threat_id = "2147916576"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 59 91 61 ?? 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 ?? 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SGAA_2147916724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SGAA!MTB"
        threat_id = "2147916724"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5f 0d 09 1b 59 20 00 01 00 00 58 20 ff 00 00 00 5f 0d 09 19 28 ?? 00 00 06 0d 09 7e ?? 00 00 04 08 58 61 20 ff 00 00 00 5f 0d 09 7e ?? 00 00 04 59 08 59 13 04 11 04 20 00 01 00 00 58 20 ff 00 00 00 5f 13 04 07 08 11 04 d2 9c 00 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SW_2147917686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SW!MTB"
        threat_id = "2147917686"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 08 02 8e 69 5d 1f 66 59 1f 66 58 02 08 02 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 07 08 07 8e 69 5d 1f 09 58 1f 0f 58 1f 18 59 1f 16 58 1f 16 59 91 61 02 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SX_2147917693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SX!MTB"
        threat_id = "2147917693"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {19 2c 0d 2b 0d 72 7f 00 00 70 2b 0d 2b 12 2b 17 de 1b 73 24 00 00 0a 2b ec 28 25 00 00 0a 2b ec 6f 26 00 00 0a 2b e7 0a 2b e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SY_2147917694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SY!MTB"
        threat_id = "2147917694"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 15 1d 5a 11 10 58 1f 13 5d 13 16 11 16 18 5d 16 fe 01 13 17 11 17 2c 08 00 11 16 18 5a 13 16 00 00 11 15 17 58 13 15 11 15 19 fe 04 13 18 11 18 2d cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SZ_2147917695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SZ!MTB"
        threat_id = "2147917695"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 06 91 11 07 61 11 09 59 20 00 02 00 00 58 13 0a 16 13 1b 2b 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SAK_2147917839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SAK!MTB"
        threat_id = "2147917839"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 08 5d 08 58 08 5d 13 0a 07 11 0a 91 13 0b 11 0b 11 07 61 13 0c 11 0c 11 09 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SBK_2147917840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SBK!MTB"
        threat_id = "2147917840"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 08 5d 08 58 08 5d 13 0a 07 11 0a 91 13 0b 11 0b 11 07 61 13 0c 11 0c 11 09 59 20 00 02 00 00 58 13 0d 11 0d 20 00 01 00 00 5d 20 00 04 00 00 58 13 0e 11 0e 20 00 02 00 00 5d 13 0f 16 13 1b 2b 1b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SCK_2147918588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SCK!MTB"
        threat_id = "2147918588"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 09 8e 69 5d 09 8e 69 58 09 8e 69 5d 13 07 09 11 07 91 13 08 11 06 08 5d 08 58 08 5d 13 09 07 11 09 91 11 08 61 13 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SDK_2147918592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SDK!MTB"
        threat_id = "2147918592"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 0e 91 13 0f 11 06 08 5d 08 58 13 10 11 10 08 5d 13 11 07 11 11 91 13 12 11 12 11 09 61 13 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SFK_2147919070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SFK!MTB"
        threat_id = "2147919070"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {14 0a 28 74 00 00 06 0a 06 0b de 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SARA_2147919141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SARA!MTB"
        threat_id = "2147919141"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d1 13 14 11 1d 11 09 91 13 22 11 1d 11 09 11 22 11 21 61 19 11 1f 58 61 11 34 61 d2 9c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_UKAA_2147919530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.UKAA!MTB"
        threat_id = "2147919530"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 20 ?? 40 00 00 28 ?? 01 00 06 28 ?? 00 00 0a 20 ?? 40 00 00 28 ?? 01 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a de 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_UXAA_2147919920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.UXAA!MTB"
        threat_id = "2147919920"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 06 2b 1f 00 7e ?? 00 00 04 11 06 7e ?? 00 00 04 11 06 91 20 d1 01 00 00 59 d2 9c 00 11 06 17 58 13 06 11 06 7e ?? 00 00 04 8e 69 fe 04 13 07 11 07 2d d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_UYAA_2147919921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.UYAA!MTB"
        threat_id = "2147919921"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 1b 00 7e ?? 00 00 04 06 7e ?? 00 00 04 06 91 7e ?? 00 00 04 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SGK_2147920297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SGK!MTB"
        threat_id = "2147920297"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 12 06 28 46 00 00 0a 6f 44 00 00 0a 00 07 6f 45 00 00 0a 20 00 1e 01 00 fe 04 13 08 11 08 39 0e 00 00 00 07 12 06 28 47 00 00 0a 6f 44 00 00 0a 00 00 11 05 17 58 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SHK_2147920298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SHK!MTB"
        threat_id = "2147920298"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 02 17 59 6f ?? 00 00 0a 07 8e 69 58 0d 08 02 6f ?? 00 00 0a 09 59 13 04 11 04 8d ?? 00 00 01 13 05 06 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_VRAA_2147920454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.VRAA!MTB"
        threat_id = "2147920454"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 01 11 03 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 06 13 05 20 ?? 00 00 00 fe 0e 04 00 38 ?? ff ff ff 28 ?? 00 00 0a 11 00 28 ?? 00 00 06 13 01}  //weight: 3, accuracy: Low
        $x_2_2 = {11 02 11 05 6f ?? 00 00 0a 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KAAT_2147920821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KAAT!MTB"
        threat_id = "2147920821"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 02 17 59 6f ?? 00 00 0a 07 8e 69 58 0d 08 02 6f ?? 00 00 0a 09 59 13 04 11 04 8d ?? 00 00 01 13 05 06 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_XGAA_2147921700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.XGAA!MTB"
        threat_id = "2147921700"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 08 17 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 de 20}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SJK_2147922690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SJK!MTB"
        threat_id = "2147922690"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 04 11 07 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0d 09 11 05 07 11 05 91 11 04 11 0d 95 61}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SKK_2147922693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SKK!MTB"
        threat_id = "2147922693"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 07 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 09 09 11 05 07 11 05 91 11 04 11 09 95 61 28 a7 00 00 0a 9c 11 05 17 58 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SLK_2147922695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SLK!MTB"
        threat_id = "2147922695"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 05 06 6f 8a 00 00 0a 0b 03 6f 8b 00 00 0a 19 58 04 fe 02 16 fe 01 0c 08 2c 0c}  //weight: 2, accuracy: High
        $x_1_2 = "FManagerApp.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SMK_2147922699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SMK!MTB"
        threat_id = "2147922699"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 08 59 0d 09 16 30 03 16 2b 01 17 13 04 08 19 58 04 fe 02 16 fe 01 13 05 11 05 2c 07 11 04 17 fe 01 2b 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SMK_2147922699_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SMK!MTB"
        threat_id = "2147922699"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 12 02 28 7f 00 00 0a 6f 80 00 00 0a 03 12 02 28 81 00 00 0a 6f 80 00 00 0a 03 12 02 28 82 00 00 0a 6f 80 00 00 0a 2b 0b 03 6f 83 00 00 0a 19 58 04 31 cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AUBA_2147924732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AUBA!MTB"
        threat_id = "2147924732"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 07 16 07 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 13 06 dd}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SOK_2147925576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SOK!MTB"
        threat_id = "2147925576"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 14 07 11 14 91 11 04 11 15 95 61 d2 9c 00 11 14 17 58 13 14 11 14 07 8e 69 fe 04 13 18 11 18 3a 66 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = "CS50_Medical_App.Welcome.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_KABB_2147929090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.KABB!MTB"
        threat_id = "2147929090"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 03 19 8d ?? 00 00 01 25 16 11 13 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 13 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 13 20 ff 00 00 00 5f d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {13 18 03 19 8d ?? 00 00 01 25 16 12 0d 28 ?? 00 00 0a 9c 25 17 12 0d 28 ?? 00 00 0a 9c 25 18 12 0d 28 ?? 00 00 0a 9c 11 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SPK_2147930543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SPK!MTB"
        threat_id = "2147930543"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 1f 10 5d 04 07 d8 b5 9d 02 03 04 07 05 28 69 00 00 06 07 17 d6 0b 07 02 6f bf 00 00 0a 2f 09 03 6f bc 00 00 0a 05 32 d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_ADJA_2147931167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.ADJA!MTB"
        threat_id = "2147931167"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 59 91 61 ?? 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 ?? 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_APMA_2147934749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.APMA!MTB"
        threat_id = "2147934749"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 00 00 fe 0c 01 00 8f ?? 00 00 01 25 47 fe 09 00 00 fe 0c 01 00 fe 09 00 00 8e 69 5d 91 61 d2 52 00 fe 0c 01 00 20 01 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 0c 00 00 8e 69 fe 04 fe 0e 02 00 fe 0c 02 00 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AANA_2147935130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AANA!MTB"
        threat_id = "2147935130"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 11 04 28 ?? 00 00 0a 72 ?? 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 28 ?? 00 00 0a 72 ?? 04 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 7e ?? 00 00 04 19 73 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 69 0a 08 11 04 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 09 07 7e ?? 00 00 04 16 94 06 6f ?? 00 00 0a 26 72 ?? 04 00 70 13 07 72 ?? 04 00 70 13 05 07 28 ?? 00 00 06 26 11 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AIPA_2147937105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AIPA!MTB"
        threat_id = "2147937105"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0d 11 0d 2c 3c 09 14 72 3f 27 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 01 00 0a 28 ?? 00 00 0a 13 05 11 04 11 05 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 0c 11 0b 12 0c 28 ?? 01 00 0a 13 0e 11 0e 2d c4}  //weight: 5, accuracy: Low
        $x_2_2 = "L o a d" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SQK_2147937549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SQK!MTB"
        threat_id = "2147937549"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 11 0d 1f 0d 5a 11 08 19 62 61 58 13 08 00 11 0c 17 58 13 0c 11 0c 11 0b}  //weight: 2, accuracy: High
        $x_2_2 = "AttendanceTracker.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_SRK_2147940179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.SRK!MTB"
        threat_id = "2147940179"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 10 11 05 91 6f f2 00 00 0a 11 05 17 58 13 05 11 05 11 06 fe 04 13 11 11 11 2d e3}  //weight: 2, accuracy: High
        $x_2_2 = "$649607e4-8d33-426c-b3ba-6745602b9f3b" ascii //weight: 2
        $x_2_3 = "Book_Mgt_System.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Remcos_AROA_2147941513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Remcos.AROA!MTB"
        threat_id = "2147941513"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remcos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 05 03 11 05 91 08 61 06 11 04 91 61 b4 9c 11 04 7e ?? 01 00 04 02 28 ?? 01 00 06 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 c8 7e ?? 02 00 04 09 74 ?? 00 00 01 03 8e b7 18 da 17 d6 8d ?? 00 00 01 28 ?? 02 00 06 74 ?? 00 00 1b 0d 09 13 07 de 65}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

