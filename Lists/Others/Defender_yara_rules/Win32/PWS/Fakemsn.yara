rule PWS_Win32_Fakemsn_E_2147646564_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fakemsn.E"
        threat_id = "2147646564"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemsn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {89 45 ec c7 45 f0 01 00 00 00 8b 45 fc 8b 55 f0 0f b6 74 10 ff 8b c7 c1 e0 08 03 f0 8b fe 83 c3 08 83 fb 06}  //weight: 4, accuracy: High
        $x_4_2 = {83 eb 06 8b cb b8 01 00 00 00 d3 e0 50 8b c7 5a 8b ca}  //weight: 4, accuracy: High
        $x_4_3 = {8b 55 b8 8b 45 f8 8b 80 20 04 00 00 8b 80 70 02 00 00 8b 08 ff 51 74 8d 45 b4}  //weight: 4, accuracy: High
        $x_1_4 = "\\msnlive.log" ascii //weight: 1
        $x_1_5 = "php.rodatnoc/moc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Fakemsn_F_2147650577_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fakemsn.F"
        threat_id = "2147650577"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemsn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "alguem me ajuda a intender!" ascii //weight: 1
        $x_1_2 = "jeratinho@hotmail.com" ascii //weight: 1
        $x_1_3 = "\\Borland\\Delphi\\" wide //weight: 1
        $x_1_4 = "vel entrar com seu Windows Live ID" wide //weight: 1
        $x_1_5 = "Example555@hotmail.com" wide //weight: 1
        $x_1_6 = "baixaconfig true - conectado" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Fakemsn_H_2147654660_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fakemsn.H"
        threat_id = "2147654660"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemsn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "insere.php" wide //weight: 1
        $x_1_2 = "msnmsgr.exe" ascii //weight: 1
        $x_1_3 = {0a 49 6e 76 69 73 69 76 65 6c 31 c0 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fakemsn_L_2147659438_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fakemsn.L"
        threat_id = "2147659438"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemsn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskkill /im msnmsgr.exe /f" ascii //weight: 1
        $x_1_2 = "/upload.php" wide //weight: 1
        $x_1_3 = {3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 (66|67) 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "Sign In" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fakemsn_P_2147660509_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fakemsn.P"
        threat_id = "2147660509"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemsn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 6c 6f 67 00 [0-3] 00 57 69 6e 64 6f 77 73 20 4c 69 76 65 20 4d 65 73 73 65 6e 67 65 72 00 [0-5] 64 69 67 6f 20 64 65 20 65 72 72 6f 3a}  //weight: 1, accuracy: Low
        $x_1_2 = "titulo=Xx Smalville xX" ascii //weight: 1
        $x_1_3 = "Prjmsn" ascii //weight: 1
        $x_1_4 = {00 40 67 6d 61 69 6c 2e 63 6f 6d 00 [0-11] 00 70 72 61 71 75 65 6d 3d 00 [0-11] 00 70 72 61 71 75 65 6d 31 3d 00 [0-11] 00 70 72 61 71 75 65 6d 32 3d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fakemsn_R_2147660638_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fakemsn.R"
        threat_id = "2147660638"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakemsn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cbxlogin" ascii //weight: 1
        $x_1_2 = "edtsenha" ascii //weight: 1
        $x_1_3 = "Tfrmmsn" ascii //weight: 1
        $x_1_4 = {65 78 65 6d 70 6c (65|6f) 35 35 35 40}  //weight: 1, accuracy: Low
        $x_1_5 = "Insira sua senha" ascii //weight: 1
        $x_10_6 = "Windows Live Messenger" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

