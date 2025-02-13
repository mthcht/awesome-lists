rule Trojan_Win32_BravePrince_A_2147725912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BravePrince.A!dha"
        threat_id = "2147725912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BravePrince"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "A474D52D-8C44-C67D-BBFB-D513232F8A17" ascii //weight: 10
        $x_10_2 = {00 77 77 77 2e 62 72 61 76 65 70 72 69 6e 63 65 2e 63 6f 6d 00}  //weight: 10, accuracy: High
        $x_5_3 = "\\taskkill /f /im daumcleaner.exe" ascii //weight: 5
        $x_5_4 = {00 45 6e 64 20 52 65 71 20 66 61 69 6c 65 64 00}  //weight: 5, accuracy: High
        $x_5_5 = {00 61 64 64 69 74 69 6f 6e 61 6c 20 68 65 61 64 65 72 20 66 61 69 6c 65 64 2e 2e 2e 00}  //weight: 5, accuracy: High
        $x_5_6 = {00 53 65 6e 64 52 65 71 20 66 61 69 6c 65 64 00}  //weight: 5, accuracy: High
        $x_5_7 = {00 5c 50 49 5f 30 30 ?? 2e 64 61 74 00}  //weight: 5, accuracy: Low
        $x_5_8 = "---------------------------%04d%04d%04d%04d" ascii //weight: 5
        $x_5_9 = {00 6d 73 31 32 2e 61 63 6d 00}  //weight: 5, accuracy: High
        $x_5_10 = {00 30 34 64 25 30 34 64 25 30 34 64 25 30 34 64 00 20 26 20 61 72 70 20 2d 61 20 3e 3e 22 00}  //weight: 5, accuracy: High
        $x_5_11 = {00 25 30 38 58 2d 25 30 38 58 2d 25 30 38 58 2d 25 30 38 58 00 25 30 38 58 25 30 38 58 25 30 38 58 25 30 38 58 00}  //weight: 5, accuracy: High
        $x_3_12 = {00 22 20 2f 73 20 2f 61 20 3e 3e 22 00 63 6d 64 2e 65 78 65 20 2f 63 20 64 69 72 20 22 00}  //weight: 3, accuracy: High
        $x_3_13 = {00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 20 52 75 6e 00}  //weight: 3, accuracy: High
        $x_3_14 = "%s\\Cache%04d.dat" ascii //weight: 3
        $x_3_15 = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3" ascii //weight: 3
        $x_3_16 = "%s\\%s_%03d" ascii //weight: 3
        $x_3_17 = "%s\\mg_%04d" ascii //weight: 3
        $x_3_18 = {00 4d 6f 6e 74 67 6f 6d 65 72 79 28 29 00}  //weight: 3, accuracy: High
        $x_1_19 = {00 25 73 5c 2a 2e 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_20 = "Enum CreateThread() failed:" ascii //weight: 1
        $x_1_21 = "InternetWriteFile failed" ascii //weight: 1
        $x_1_22 = {00 41 63 74 69 6f 6e 20 43 65 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_23 = {00 4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 72 76 3a 31 32 2e 30 29 20 47 65 63 6b 6f 2f 32 30 31 30 30 31 30 31 20 46 69 72 65 66 6f 78 2f 31 32 2e 30 00}  //weight: 1, accuracy: High
        $x_1_24 = {00 72 65 71 75 65 73 74 20 66 61 69 6c 65 64 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_25 = {00 70 63 61 63 6c 69 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_26 = "%02d%02d%02d%02d%01d_1" ascii //weight: 1
        $x_1_27 = "%04d%02d%02d%02d%02d%02d" ascii //weight: 1
        $x_1_28 = {00 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 00}  //weight: 1, accuracy: High
        $x_1_29 = {00 63 3a 5c 75 73 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_30 = "moveToFolderId" ascii //weight: 1
        $x_1_31 = "https://logins.daum.net/accounts/" ascii //weight: 1
        $x_1_32 = "https://mail.daum.net/login?url=http%3A%2F%2Fmail.daum.net%2F" ascii //weight: 1
        $x_1_33 = "</P>\\r\\n<P>&nbsp;</P>\\r\\n<P>&nbsp;</P>\\r\\n<P>&nbsp;</P></div></td></tr></table>\"," ascii //weight: 1
        $x_1_34 = "{\"subject\":\"\",\"contents\":\"<table class = \\\"txc-wrapper\\\" border=\\\"0\\\" cellspacing=\\\"0\\\" cellpadding=" ascii //weight: 1
        $x_1_35 = "{\"composerId\":\"\",\"toList\":[{\"name\":\"\",\"addr\":\"\"}],\"ccList\":[],\"bccList\":[],\"from\":{\"addr\":\"\",\"name\":\"\"}" ascii //weight: 1
        $x_1_36 = "https://cmail.daum.net/v2/" ascii //weight: 1
        $x_1_37 = "http://mail.daum.net/kocl/" ascii //weight: 1
        $x_1_38 = "https://mail.daum.net" ascii //weight: 1
        $x_1_39 = "https://logins.daum.net/accounts/logout.do?url=http%3A%2F%2Fwww.daum.net%2F%3Fnil_profile%3Dlogout" ascii //weight: 1
        $x_1_40 = {00 68 74 74 70 3a 2f 2f 6e 69 64 2d 68 65 6c 70 2d 70 63 68 61 6e 67 65 2e 61 74 77 65 62 70 61 67 65 73 2e 63 6f 6d 2f 68 6f 6d 65 2f 77 65 62 2f 70 6f 73 74 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_41 = {00 68 74 74 70 3a 2f 2f 6e 69 64 2d 68 65 6c 70 2d 70 63 68 61 6e 67 65 2e 61 74 77 65 62 70 61 67 65 73 2e 63 6f 6d 2f 68 6f 6d 65 2f 77 65 62 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f 66 69 6c 65 6e 61 6d 65 3d 25 73 26 6b 65 79 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 21 of ($x_1_*))) or
            ((4 of ($x_3_*) and 18 of ($x_1_*))) or
            ((5 of ($x_3_*) and 15 of ($x_1_*))) or
            ((6 of ($x_3_*) and 12 of ($x_1_*))) or
            ((7 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 22 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 19 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_3_*) and 16 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_3_*) and 13 of ($x_1_*))) or
            ((1 of ($x_5_*) and 5 of ($x_3_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 7 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*) and 20 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((2 of ($x_5_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((2 of ($x_5_*) and 4 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_5_*) and 5 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*) and 6 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 7 of ($x_3_*))) or
            ((3 of ($x_5_*) and 15 of ($x_1_*))) or
            ((3 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((3 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((3 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((3 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_5_*) and 5 of ($x_3_*))) or
            ((4 of ($x_5_*) and 10 of ($x_1_*))) or
            ((4 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((4 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*) and 4 of ($x_3_*))) or
            ((5 of ($x_5_*) and 5 of ($x_1_*))) or
            ((5 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((5 of ($x_5_*) and 2 of ($x_3_*))) or
            ((6 of ($x_5_*))) or
            ((1 of ($x_10_*) and 20 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 17 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_3_*) and 14 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_3_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 6 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 7 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*) and 9 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_3_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_3_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_3_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_10_*) and 10 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 4 of ($x_3_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_3_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

