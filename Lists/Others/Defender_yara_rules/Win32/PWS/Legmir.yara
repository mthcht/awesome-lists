rule PWS_Win32_Legmir_B_2147555054_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Legmir.B"
        threat_id = "2147555054"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Legmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "42"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "legend of mir2" ascii //weight: 10
        $x_10_2 = "/imail/sendmail.asp?tomail=" ascii //weight: 10
        $x_10_3 = {50 4f 53 54 00 00 00 00 48 54 54 50 2f 31 2e 30}  //weight: 10, accuracy: High
        $x_10_4 = "Lineage Windows Client" ascii //weight: 10
        $x_1_5 = "EGhost.exe" ascii //weight: 1
        $x_1_6 = "PasswordGuard.exe" ascii //weight: 1
        $x_1_7 = "kvapfw.exe" ascii //weight: 1
        $x_1_8 = "Iparmor.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Legmir_E_2147574406_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Legmir.E!dll"
        threat_id = "2147574406"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Legmir"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "%s?id=%s&p=%s&q=%s&lck=%s&srv=%s&js1=%s&id1=%s&dj1=%d&pc=%s" ascii //weight: 5
        $x_5_2 = "%s?server=%s&user=%s&psw=%s&lockpsw=%s&role=%s&level=%d&roles=%s" ascii //weight: 5
        $x_5_3 = "lin.asp?srv=%s&id=%s&p=%s&s=%s&ss=%s&js=%s&gj=%s&dj=%d&yz=%s" ascii //weight: 5
        $x_2_4 = "%s/ti.asp?s=%s&u=%s" ascii //weight: 2
        $x_1_5 = "Forthgoer" ascii //weight: 1
        $x_1_6 = "SetWindowsHookExA" ascii //weight: 1
        $x_1_7 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_8 = "SeDebugPrivilege" ascii //weight: 1
        $x_1_9 = "mrecv" ascii //weight: 1
        $x_1_10 = "msend" ascii //weight: 1
        $x_1_11 = "WSGAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Legmir_G_2147597322_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Legmir.G"
        threat_id = "2147597322"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Legmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9b 83 83 83 80 c2 88 8d 98 d7 9b 83 83 83 80 d4 d4 c2 88 8d 98 d7 81 85 9e dd c2 88 8d 98 d7 ec 5e 7c 87 77}  //weight: 1, accuracy: High
        $x_1_2 = {9b 83 83 83 80 c2 89 94 89 d7 81 85 9e c2 89 94 89 d7 ec 83 e5 4f}  //weight: 1, accuracy: High
        $x_1_3 = {64 6c 6c 2e 64 6c 6c 00 57 53 50 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Legmir_A_2147622114_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Legmir.A"
        threat_id = "2147622114"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Legmir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gethostbyname" ascii //weight: 1
        $x_1_2 = "AUTH LOGIN" ascii //weight: 1
        $x_1_3 = "RCPT TO: <" ascii //weight: 1
        $x_1_4 = "MAIL FROM:" ascii //weight: 1
        $x_1_5 = {4d 53 5f 44 6f 73 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

