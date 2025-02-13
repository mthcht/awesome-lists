rule PWS_Win32_Bzub_2147576295_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bzub"
        threat_id = "2147576295"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bzub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 51 8b 45 08 53 56 57 66 81 38 4d 5a 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {50 45 00 00 0f 85}  //weight: 1, accuracy: High
        $x_2_3 = {c1 e9 1d c1 ee 1e 83 e1 01 83 e6 01 c1 ef 1f f6 43 03 02}  //weight: 2, accuracy: High
        $x_2_4 = {8b 45 fc 8d ?? 01 8a c1 f6 e9 f6 e9}  //weight: 2, accuracy: Low
        $x_2_5 = {74 33 a9 00 00 00 80 74 07 25 ff ff 00 00 eb 05 03 c5 83 c0 02 50 ff 74 24 18}  //weight: 2, accuracy: High
        $x_2_6 = {83 44 24 1c 04 83 c6 04 eb c8 83 64 24 10 00 83 7c 24 10 00 74 0d 83 c7 14}  //weight: 2, accuracy: High
        $x_2_7 = {18 02 52 65 61 64 46 69 6c 65 00 00 12 01 47 65}  //weight: 2, accuracy: High
        $n_100_8 = "pdfsdkcom.DLL" ascii //weight: -100
        $n_100_9 = ".vividas.com/player" ascii //weight: -100
        $n_5_10 = "OCXPLAY.VPlayerPropPage.1" ascii //weight: -5
        $n_100_11 = "VeryPDF" ascii //weight: -100
        $n_100_12 = {00 6d 61 78 74 68 6f 6e 5f 70 72 65 66 2e 64 6c 6c 00}  //weight: -100, accuracy: High
        $n_100_13 = {00 67 65 74 5f 6d 61 78 74 68 6f 6e 5f 68 6f 6d 65 70 61 67 65 00}  //weight: -100, accuracy: High
        $n_100_14 = {00 73 65 74 5f 6d 61 78 74 68 6f 6e 33 5f 66 61 76 6f 72 69 74 65 73 00}  //weight: -100, accuracy: High
        $n_100_15 = {00 73 65 74 5f 6d 61 78 74 68 6f 6e 35 5f 66 61 76 6f 72 69 74 65 73 00}  //weight: -100, accuracy: High
        $n_100_16 = {00 73 65 74 5f 77 6e 69 65 5f 66 61 76 6f 72 69 74 65 73 00}  //weight: -100, accuracy: High
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Bzub_2147806865_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Bzub.gen!dll"
        threat_id = "2147806865"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Bzub"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://www.e-gold.com" ascii //weight: 1
        $x_1_2 = "/acct/balance.asp" ascii //weight: 1
        $x_1_3 = "/acct/acct.asp" ascii //weight: 1
        $x_1_4 = "209.200.169.10" ascii //weight: 1
        $x_1_5 = "UpperHost" ascii //weight: 1
        $x_1_6 = "WinID" ascii //weight: 1
        $x_1_7 = "PStorage" ascii //weight: 1
        $x_1_8 = "AData" ascii //weight: 1
        $x_1_9 = "/acct/contactus.asp" ascii //weight: 1
        $x_1_10 = "AccountID=" ascii //weight: 1
        $x_1_11 = "PassPhrase=" ascii //weight: 1
        $x_1_12 = "application/octet-stream" ascii //weight: 1
        $x_1_13 = "CustomerEmail=" ascii //weight: 1
        $x_2_14 = "<title>e-gold Account Management</title>" ascii //weight: 2
        $x_2_15 = "Helvetica, sans-serif\" size=\"2\">" ascii //weight: 2
        $x_2_16 = "Unable to login to account" ascii //weight: 2
        $x_1_17 = "ACCOUNT DATA:" ascii //weight: 1
        $x_2_18 = "E-mail = %s" ascii //weight: 2
        $x_2_19 = "Metal = %s" ascii //weight: 2
        $x_2_20 = "Wight = %s" ascii //weight: 2
        $x_2_21 = "Equiv = %s" ascii //weight: 2
        $x_2_22 = "Value = %s" ascii //weight: 2
        $x_1_23 = "PROTECTED STORAGE:" ascii //weight: 1
        $x_2_24 = "Account Name - %s" ascii //weight: 2
        $x_2_25 = "POP3 Server - %s" ascii //weight: 2
        $x_2_26 = "POP3 User Name - %s" ascii //weight: 2
        $x_2_27 = "SMTP Email Address - %s" ascii //weight: 2
        $x_1_28 = "Internet Account Manager\\Accounts" ascii //weight: 1
        $x_2_29 = "Mail Accounts (%.8x)" ascii //weight: 2
        $x_2_30 = "HTTP/FTP Accounts (%.8x)" ascii //weight: 2
        $x_2_31 = "PassData = %" ascii //weight: 2
        $x_2_32 = "Resource = %" ascii //weight: 2
        $x_1_33 = "Windows\\CurrentVersion\\Internet" ascii //weight: 1
        $x_2_34 = "123ab%.8lx" ascii //weight: 2
        $x_2_35 = "--%s" ascii //weight: 2
        $x_3_36 = "form-data; name=\"hit\"; filename=\"%s\"" ascii //weight: 3
        $x_2_37 = "multipart/form-data; boundary=%s" ascii //weight: 2
        $x_1_38 = "CryptUnprotectData" ascii //weight: 1
        $x_1_39 = "CurrentVersion\\ShellServiceObjectDelayLoad" ascii //weight: 1
        $x_1_40 = "CLSID\\{523455E4-ABCD-ABCD-1114-D709ADD3DDAB}\\InProcServer32" ascii //weight: 1
        $x_2_41 = "256.256.256.256" ascii //weight: 2
        $x_2_42 = "[%X[%s][IP: %s %s %s]" ascii //weight: 2
        $x_2_43 = "one-time PIN" ascii //weight: 2
        $x_2_44 = ">e-mail:<" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_2_*) and 20 of ($x_1_*))) or
            ((11 of ($x_2_*) and 18 of ($x_1_*))) or
            ((12 of ($x_2_*) and 16 of ($x_1_*))) or
            ((13 of ($x_2_*) and 14 of ($x_1_*))) or
            ((14 of ($x_2_*) and 12 of ($x_1_*))) or
            ((15 of ($x_2_*) and 10 of ($x_1_*))) or
            ((16 of ($x_2_*) and 8 of ($x_1_*))) or
            ((17 of ($x_2_*) and 6 of ($x_1_*))) or
            ((18 of ($x_2_*) and 4 of ($x_1_*))) or
            ((19 of ($x_2_*) and 2 of ($x_1_*))) or
            ((20 of ($x_2_*))) or
            ((1 of ($x_3_*) and 9 of ($x_2_*) and 19 of ($x_1_*))) or
            ((1 of ($x_3_*) and 10 of ($x_2_*) and 17 of ($x_1_*))) or
            ((1 of ($x_3_*) and 11 of ($x_2_*) and 15 of ($x_1_*))) or
            ((1 of ($x_3_*) and 12 of ($x_2_*) and 13 of ($x_1_*))) or
            ((1 of ($x_3_*) and 13 of ($x_2_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 14 of ($x_2_*) and 9 of ($x_1_*))) or
            ((1 of ($x_3_*) and 15 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 16 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 17 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 18 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 19 of ($x_2_*))) or
            (all of ($x*))
        )
}

