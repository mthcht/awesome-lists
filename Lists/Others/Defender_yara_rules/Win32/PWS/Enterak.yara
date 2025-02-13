rule PWS_Win32_Enterak_B_2147678899_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Enterak.B"
        threat_id = "2147678899"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Enterak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3f 75 70 3d 25 73 26 70 70 3d 25 73 26 73 73 70 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 70 5f 6d 6e 79 5f 62 61 6c 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 6d 5f 70 5f 55 73 65 72 49 64 00}  //weight: 1, accuracy: High
        $x_2_4 = {66 3b c3 74 11 66 3d 06 00 74 0b 66 3d 05 00 74 05 bd 02 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Enterak_A_2147696358_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Enterak.A"
        threat_id = "2147696358"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Enterak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".asp?up=%s&pp=%s" ascii //weight: 1
        $x_1_2 = "\\res\\PCOTP.okf" ascii //weight: 1
        $x_1_3 = "Lineage Windows Client" ascii //weight: 1
        $x_1_4 = "Diablo III.exe" ascii //weight: 1
        $x_1_5 = "CONFIG_CHANNEL_SELECT_SERVER=" ascii //weight: 1
        $x_1_6 = "V3LTray.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Enterak_A_2147696358_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Enterak.A"
        threat_id = "2147696358"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Enterak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = ".asp?up=%s&pp=%s" ascii //weight: 2
        $x_1_2 = {74 65 65 6e 63 61 73 68 [0-5] 68 61 70 70 79 6d 6f 6e 65 79 [0-5] 63 75 6c 74 75 72 65 6c 61 6e 64}  //weight: 1, accuracy: Low
        $x_2_3 = "}document.cookie='IEPROXY=U:'+frm_login.id.value+'/'+login_site+'|'+strPwd+':';" ascii //weight: 2
        $x_1_4 = "&p_level=" ascii //weight: 1
        $x_1_5 = "&p_mny_bal=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Enterak_A_2147696358_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Enterak.A"
        threat_id = "2147696358"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Enterak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LoginContainer:txtPassw" ascii //weight: 1
        $x_1_2 = ":txtEmailAccount" ascii //weight: 1
        $x_1_3 = "lin.asp+http:" ascii //weight: 1
        $x_2_4 = {2e 61 73 70 3f 75 [0-1] 3d 25 73 26 70 [0-1] 3d 25 73}  //weight: 2, accuracy: Low
        $x_1_5 = {25 73 3f 61 [0-1] 3d 25 73 26 73 [0-1] 3d 25 73 26}  //weight: 1, accuracy: Low
        $x_1_6 = "id_hidden" ascii //weight: 1
        $x_1_7 = "txtMemberID" ascii //weight: 1
        $x_2_8 = {26 73 74 72 53 53 4e 3d 00}  //weight: 2, accuracy: High
        $x_1_9 = "\\res\\PCOTP.okf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Enterak_A_2147696358_3
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Enterak.A"
        threat_id = "2147696358"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Enterak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "42"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 87 b4 00 00 00 be ?? ?? 00 10 ff 36 57 e8 ?? ?? 00 00 59 85 c0 59 74 10 83 c6 04 81 fe ?? ?? 00 10 7c e7 e9 91 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {5c 66 6f 6f 6f 6c 2e 64 61 74 00}  //weight: 10, accuracy: High
        $x_10_3 = {4c 6f 67 69 6e 43 6f 6e 74 61 69 6e 65 72 3a 74 78 74 50 61 73 73 77 64 00}  //weight: 10, accuracy: High
        $x_10_4 = "IEHelper Module" wide //weight: 10
        $x_1_5 = "earthworm2" ascii //weight: 1
        $x_1_6 = "turtle2" ascii //weight: 1
        $x_1_7 = ".hangame.com" ascii //weight: 1
        $x_1_8 = ".nexon.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

