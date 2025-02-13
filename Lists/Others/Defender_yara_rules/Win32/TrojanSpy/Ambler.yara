rule TrojanSpy_Win32_Ambler_C_2147598281_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.C"
        threat_id = "2147598281"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {59 6a 01 59 3b c1 7e 0e 0f be b1 ?? ?? ?? ?? 33 d6 41 3b c8 7c f2 3b 15 ?? ?? ?? ?? 74 07 33 c0 e9 ?? ?? 00 00}  //weight: 15, accuracy: Low
        $x_2_2 = "OVERS=%s" ascii //weight: 2
        $x_2_3 = "CLICKS=%s" ascii //weight: 2
        $x_2_4 = "KEYSREAD:%s" ascii //weight: 2
        $x_2_5 = "KEYLOGGED:%s KEYSREAD:%s" ascii //weight: 2
        $x_1_6 = "\\ps.dat" ascii //weight: 1
        $x_1_7 = "\\alog.txt" ascii //weight: 1
        $x_1_8 = "\\accs.txt" ascii //weight: 1
        $x_1_9 = "\\boa.dat" ascii //weight: 1
        $x_1_10 = "nethelper" ascii //weight: 1
        $x_1_11 = "HelperMutex" ascii //weight: 1
        $x_1_12 = "subject=NONE&content=" ascii //weight: 1
        $x_1_13 = "subject=%s&content=" ascii //weight: 1
        $x_1_14 = "\\commands.xml" ascii //weight: 1
        $x_1_15 = "\\commandhelper.xml" ascii //weight: 1
        $x_1_16 = "\\nethelper.xml" ascii //weight: 1
        $x_1_17 = "\\nethelper2.xml" ascii //weight: 1
        $x_1_18 = "\\helper.xml" ascii //weight: 1
        $x_1_19 = "\\helper2.xml" ascii //weight: 1
        $x_1_20 = "\\helper.dll" ascii //weight: 1
        $x_1_21 = "\\nethelper.dll" ascii //weight: 1
        $x_1_22 = "\\nethelper2.dll" ascii //weight: 1
        $x_1_23 = "KILLWINANDREBOOT" ascii //weight: 1
        $x_1_24 = "KILLWIN" ascii //weight: 1
        $x_1_25 = "UNBLOCKSITE" ascii //weight: 1
        $x_1_26 = "BLOCKSITE" ascii //weight: 1
        $x_1_27 = "DELETEBOFAKEYS" ascii //weight: 1
        $x_1_28 = "COPYBOFAKEYS" ascii //weight: 1
        $x_1_29 = "DOWNLOAD" ascii //weight: 1
        $x_1_30 = "LOADXML" ascii //weight: 1
        $x_1_31 = "DELETESELF" ascii //weight: 1
        $x_1_32 = "DELETECOOKIES" ascii //weight: 1
        $x_1_33 = "HOSTADD" ascii //weight: 1
        $x_1_34 = "mailscript" ascii //weight: 1
        $x_1_35 = "newuserscript" ascii //weight: 1
        $x_1_36 = "ackcommandscript" ascii //weight: 1
        $x_1_37 = "commandscript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((16 of ($x_1_*))) or
            ((1 of ($x_2_*) and 14 of ($x_1_*))) or
            ((2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((3 of ($x_2_*) and 10 of ($x_1_*))) or
            ((4 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_1_*))) or
            ((1 of ($x_15_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ambler_D_2147598323_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.D"
        threat_id = "2147598323"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 33 c9 85 c0 7e 09 80 34 31 ?? 41 3b c8 7c f7 5e c3}  //weight: 1, accuracy: Low
        $x_1_2 = {76 09 80 34 38 ?? 40 3b c6 72 f7}  //weight: 1, accuracy: Low
        $x_1_3 = {8b c2 8b d8 8b c3 8b d0 8b c1 e2 f4 [0-4] e8}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 02 5f c6 06 4d 39 7d f8 c6 46 01 5a 76 25 89 5d fc 29 75 fc 8b c7 6a 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Ambler_E_2147598324_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.E"
        threat_id = "2147598324"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 39 51 08 7e 0f 8b 41 04 80 34 10 ?? 03 c2 42 3b [0-2] 7c f1 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {7e 1a 53 56 8b 41 04 6a ?? 5b 8d 34 07 8b c7 99 f7 fb 30 16 47 3b 79 08 7c ea}  //weight: 1, accuracy: Low
        $x_2_3 = {ff 75 0c ff d7 59 85 c0 59 75 10 68 ?? ?? ?? ?? ff 75 08 ff d7 59 85 c0 59 74 08 6a 01 58 e9 ?? 01 00 00 8a 45 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ambler_F_2147605171_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.F"
        threat_id = "2147605171"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {56 8b 74 24 08 56 e8 ?? ?? ?? ?? 59 33 c9 85 c0 7e 09 80 34 31 ?? 41 3b c8 7c f7 5e c3}  //weight: 3, accuracy: Low
        $x_3_2 = {99 4a ad 42 03 45 0c 50 e8 97 ff ff ff 39 d8 75 f1}  //weight: 3, accuracy: High
        $x_3_3 = {46 2d 2d 37 64 36 31 35 62 31 36 31 62 30 36 34 61 00 04 00 00 00 00 00}  //weight: 3, accuracy: Low
        $x_2_4 = {4c 4f 41 44 58 4d 4c 00 (3d|3e) 00 00 [0-5] 76 61 6c 75 65 3d}  //weight: 2, accuracy: Low
        $x_2_5 = {47 45 54 46 49 4c 45 53 00 00 00 00 4c 4f 41 44 58 4d 4c 00 63 69 64 00}  //weight: 2, accuracy: High
        $x_2_6 = {4c 4f 41 44 58 4d 4c 00 47 45 54 46 49 4c 45 53 00}  //weight: 2, accuracy: High
        $x_2_7 = {25 73 5c 25 73 5f 25 75 2e 62 6d 70 00}  //weight: 2, accuracy: High
        $x_2_8 = {25 00 53 00 5c 00 25 00 53 00 5f 00 25 00 53 00 25 00 53 00 2e 00 6a 00 70 00 67 00 00 00}  //weight: 2, accuracy: High
        $x_2_9 = {25 30 32 64 25 30 32 64 25 30 32 64 5f 25 30 34 64 00 00 00 25 30 32 64 25 30 32 64 25 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ambler_K_2147628021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.K"
        threat_id = "2147628021"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 08 84 c9 74 08 80 f1 ?? 88 08 40 eb f2}  //weight: 2, accuracy: Low
        $x_2_2 = {2b fe 80 71 ff ?? 80 31 ?? 80 71 01 ?? 83 c1 03 83 c2 03 8d 1c 0f 3b d8 72 e8}  //weight: 2, accuracy: Low
        $x_1_3 = "_beginthreadex" ascii //weight: 1
        $x_1_4 = "HttpSendRequestA" ascii //weight: 1
        $x_1_5 = "userid=%s" ascii //weight: 1
        $x_1_6 = "<RUN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ambler_L_2147637714_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.L"
        threat_id = "2147637714"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 5b 25 73 5d 0a 4b 45 59 4c 4f 47 47 45 44 3a 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_2 = "rundll32.exe \"%s\", InstllH" ascii //weight: 1
        $x_1_3 = {8b 45 08 8b cf 2b c7 8b d6 8a 1c 08 80 f3 0e 88 19 41 4a 75 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Ambler_N_2147638903_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.N"
        threat_id = "2147638903"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 33 c9 85 c0 7e 09 80 34 31 ?? 41 3b c8 7c f7 5e c3}  //weight: 2, accuracy: Low
        $x_2_2 = {45 47 49 6e 6a 65 63 74 5f 44 4c 4c 2e 64 6c 6c 00 47 6d 4d 79 49 6e 69 74 50 6f 69 6e 74 00 47 6d 57 72 69 74 65 52 65 67 41 6e 64 49 6d 70 6f 72 74 00 49 6e 6a 65 63 74 50 72 6f 63 65 73 73 00}  //weight: 2, accuracy: High
        $x_1_3 = "http://%s/files/%s%s/" ascii //weight: 1
        $x_1_4 = "Order_sel.php?Cookie=MAC|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ambler_Q_2147650190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.Q"
        threat_id = "2147650190"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%s_skey_%s_%s.cab" ascii //weight: 1
        $x_5_2 = {66 69 72 65 66 6f 78 2e 65 00}  //weight: 5, accuracy: High
        $x_5_3 = {6a 40 6a 1e 53 ff 15 ?? ?? ?? ?? 8d 43 05 89 33 50 56 89 45 f8 e8 ?? ?? ?? ?? 83 c4 08 88 43 04 8b 45 fc 8d 55 fc 2b fe 52 50 83 ef 05}  //weight: 5, accuracy: Low
        $x_1_4 = {00 6e 6f 6c 6f 67 00 00 00 61 62 00 00 64 6d 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ambler_R_2147652573_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.R"
        threat_id = "2147652573"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 40 3b 45 fc 73 69 0f be 45 f8 50 8b 45 08 03 45 f4 0f be 00 50 e8}  //weight: 2, accuracy: High
        $x_2_2 = "*******GRABBED BALANCE*******" ascii //weight: 2
        $x_1_3 = {5c 79 79 74 78 74 74 00 5c 63 74 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 65 78 70 6c 6f 72 65 2e 65 00 [0-5] 69 72 65 66 6f 78 2e 65 00 [0-5] 72 75 6e 64 6c 6c 33 32 2e 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {00 6e 6f 6c 6f 67 00 00 00 61 62 00 00 64 6d 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Ambler_S_2147652945_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Ambler.S"
        threat_id = "2147652945"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ambler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c5 8b d8 8b d3 8b c2 8b c1 33 d9 33 d1 8b c3 03 c2 e2 ec}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 08 f7 d0 23 44 24 04 c3 8b 44 24 04 f7 d0 23 44 24 08 c3 8b 44 24 04 0b 44 24 08 c3}  //weight: 1, accuracy: High
        $x_1_3 = {8d 56 fb 89 50 01 0f b6 c9 c6 40 05 e9 8d 4c 31 f6 89 48 06 8d 47 0a}  //weight: 1, accuracy: High
        $x_1_4 = {2b fe ff 75 fc 83 ef 05 c6 06 e9 89 7e 01 6a 05}  //weight: 1, accuracy: High
        $x_2_5 = {88 46 01 8b 45 08 83 c6 03 83 c4 18 03 c6 83 c7 03 3b 45 fc 72}  //weight: 2, accuracy: High
        $x_2_6 = "***GRABBED BALANCE***" ascii //weight: 2
        $x_1_7 = "privacy.clearOnShutdown.cookies\", false" ascii //weight: 1
        $x_1_8 = "security.warn_submit_insecure\",false" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

