rule PWS_Win32_VB_HB_2147515526_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.HB"
        threat_id = "2147515526"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Internet Explorer\\TypedURLs" wide //weight: 1
        $x_1_2 = "CMSNMessengerPasswords" ascii //weight: 1
        $x_1_3 = "COutlookAccounts" ascii //weight: 1
        $x_1_4 = "TDisableSavePass" ascii //weight: 1
        $x_1_5 = "COutlookAccount" ascii //weight: 1
        $x_1_6 = "lvMSNMessenger" ascii //weight: 1
        $x_1_7 = "TGetYahooClass" ascii //weight: 1
        $x_1_8 = "CIE7Passwords" ascii //weight: 1
        $x_1_9 = "YahooPassword" ascii //weight: 1
        $x_1_10 = "CIEPasswords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VB_AOA_2147596908_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.AOA"
        threat_id = "2147596908"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "MSVBVM60.DLL" ascii //weight: 10
        $x_10_2 = "Gold e cash Hack - By L0G4N" ascii //weight: 10
        $x_10_3 = "C:\\Documents and Settings\\Diego\\Desktop\\gold hack\\Project1.vbp" wide //weight: 10
        $x_1_4 = "Adicionar 430 GP Quando possivel..." ascii //weight: 1
        $x_1_5 = "Ocultar Login (Recomendado!)" ascii //weight: 1
        $x_1_6 = "Tentar Ocultar-se do Hack Shield" ascii //weight: 1
        $x_1_7 = "http://wgdteam.jconserv.net" ascii //weight: 1
        $x_1_8 = "Login =" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_VB_CE_2147597158_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.CE"
        threat_id = "2147597158"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "software\\microsoft\\windows\\currentversion\\run" wide //weight: 1
        $x_1_2 = {08 00 00 00 43 00 44 00 20 00 22 00 00 00 00 00 02 00 00 00 22 00 00 00 04 00 00 00 01 00 88 00 0c 00 00 00 53 00 54 00 41 00 52 00 54 00 20 00}  //weight: 1, accuracy: High
        $x_1_3 = "path" wide //weight: 1
        $x_1_4 = "open" wide //weight: 1
        $x_1_5 = {50 ff d6 8b d0 8d 4d d4 ff d7 50 68 ?? ?? ?? ?? ff d6 8b d0 8d 4d d0 ff d7 50 53 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8d 4d d0 51 8d 55 d4 52 6a 02 ff 15 ?? ?? ?? ?? 83 c4 18 53 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? e9 ?? ?? ?? ?? ff d6 8b d0 8d 4d d4 ff d7 8b 55 10 50 8b 02 50 ff d6 8b d0 8d 4d d0 ff d7 50 68 ?? ?? ?? ?? ff d6 8b d0 8d 4d cc ff d7 50 53 6a ff 68 02 02 00 00 ff 15 ?? ?? ?? ?? 8d 4d cc 51 8d 55 d0 52 8d 45 d4 50 6a 03 ff 15 ?? ?? ?? ?? 8b 4d 0c 8b 11 83 c4 10 68 ?? ?? ?? ?? 52 ff d6 8b d0 8d 4d d4 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VB_DA_2147605031_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.DA"
        threat_id = "2147605031"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "131"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Demon-Child" wide //weight: 10
        $x_10_2 = "Hacked Yahoo!Mess Account" wide //weight: 10
        $x_10_3 = "E:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii //weight: 10
        $x_10_4 = "E:\\WINDOWS\\system32\\MSHTML.TLB" ascii //weight: 10
        $x_10_5 = "username" ascii //weight: 10
        $x_10_6 = "password" ascii //weight: 10
        $x_10_7 = "Net Stop " wide //weight: 10
        $x_10_8 = "Security Center" wide //weight: 10
        $x_10_9 = "YahooBuddyMain" wide //weight: 10
        $x_10_10 = "cmd /c rd \"%programfiles%\\Yahoo!\\Messenger\\Profiles\" /s /q" wide //weight: 10
        $x_10_11 = "cmd /c rd \"c:\\Yahoo!\\Messenger\\Profiles\" /s /q" wide //weight: 10
        $x_10_12 = "Sign in as in&visible to everyone" wide //weight: 10
        $x_10_13 = "%systemroot%\\system32\\ipconfig.exe > %SYSTEMROOT%\\system32" wide //weight: 10
        $x_1_14 = "&Remember my ID && password" wide //weight: 1
        $x_1_15 = "YDisconnectedWindow" wide //weight: 1
        $x_1_16 = "E:\\Documents and Settings\\Advance Programmer\\My Documents\\erw\\demon\\ee\\Project1.vbp" wide //weight: 1
        $x_1_17 = "Hacked Web Pass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((13 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_VB_Q_2147624684_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.Q"
        threat_id = "2147624684"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mx1.mail.yahoo.com" wide //weight: 1
        $x_1_2 = "tmrGETKEY" ascii //weight: 1
        $x_1_3 = {50 51 c7 45 ?? 01 80 ff ff c7 45 ?? 02 80 00 00 ff 15 ?? ?? ?? ?? 66 85 c0 0f 84 ?? ?? 00 00 66 83 ff 01 75 0a ba ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VB_AW_2147625214_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.AW"
        threat_id = "2147625214"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 69 73 74 50 72 6f 63 65 73 73 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {6c 69 73 74 65 72 4d 73 6e 43 6f 6e 74 61 63 74 73 00 00 00 6c 69 73 74 65 72 6c 69 6e 6b 00 00 52 61 6e 64}  //weight: 1, accuracy: High
        $x_1_3 = {6d 64 6c 57 69 6e 73 6f 63 6b 00 00 6d 64 6c 57 69 6e 73 6f 63 6b 41 50 49 73 00 00 6d 6f 64 53 4d 54 50 00 6d 6f 64 5f 56 61 72 69 61 76 65 69 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VB_CT_2147643417_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.CT"
        threat_id = "2147643417"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ServiceManager" ascii //weight: 1
        $x_1_2 = "PasswordMailer" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
        $x_1_4 = "D:\\PASSWO~1\\PASSWO~1.VBP" wide //weight: 1
        $x_1_5 = "Copyright (C) Microsoft Corp." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VB_DG_2147653350_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.DG"
        threat_id = "2147653350"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\IMVU\\password\\" wide //weight: 1
        $x_1_2 = "SELECT * FROM logins" wide //weight: 1
        $x_1_3 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" wide //weight: 1
        $x_1_4 = "select *  from moz_logins" wide //weight: 1
        $x_1_5 = "\\KEYLOGGER\\" wide //weight: 1
        $x_1_6 = "Stealer Log" wide //weight: 1
        $x_1_7 = "Microsoft\\Security Center" wide //weight: 1
        $x_1_8 = "UACDisableNotify" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule PWS_Win32_VB_DL_2147653980_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.DL"
        threat_id = "2147653980"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeginPos" wide //weight: 1
        $x_1_2 = "HTMLbOdy" wide //weight: 1
        $x_1_3 = "smtpserverport" wide //weight: 1
        $x_2_4 = "CDO.Configuration" wide //weight: 2
        $x_2_5 = "Email : " wide //weight: 2
        $x_2_6 = "ifre : " wide //weight: 2
        $x_2_7 = "sendpassword" wide //weight: 2
        $x_3_8 = "smtp.gmail.com" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_VB_CS_2147749690_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/VB.CS!eml"
        threat_id = "2147749690"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "VB"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f c8 0f c8 89 c0 89 ff 85 c0 89 ff 89 db 89 c0 31 04 1f}  //weight: 1, accuracy: High
        $x_1_2 = {0f c8 0f c8 0f c8 0f c8 89 c0 89 c0 89 ff 0f c8 0f c8 40 00 b8 ?? ?? ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

