rule TrojanSpy_Win32_Derusbi_I_2147691846_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Derusbi.I!dha"
        threat_id = "2147691846"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NTLMSSP%c%c%c%c%c%c%c%c%c%c%c%c%c%c" ascii //weight: 1
        $x_1_2 = {72 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 61 00 75 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "GET /Photos/Query.cgi?loginid=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Derusbi_A_2147691850_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Derusbi.A!dha"
        threat_id = "2147691850"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Keylog %d chars" wide //weight: 1
        $x_1_2 = "IE account %d found" wide //weight: 1
        $x_1_3 = "AV: %s" wide //weight: 1
        $x_2_4 = "\\ziptmp$" wide //weight: 2
        $x_1_5 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_6 = "POST /Catelog/login1.asp HTTP/1.1" ascii //weight: 1
        $x_1_7 = {5c 73 79 73 74 65 6d 33 32 5c 6d 73 75 73 62 00 2e 64 61 74}  //weight: 1, accuracy: High
        $x_1_8 = "POST /photos/photo.asp HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Derusbi_B_2147691851_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Derusbi.B!dha"
        threat_id = "2147691851"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 44 46 54 4d 50 24 24 24 24 24 24 2e 31 00}  //weight: 2, accuracy: High
        $x_1_2 = "PCC_IDENT" ascii //weight: 1
        $x_1_3 = "PCC_CMD" ascii //weight: 1
        $x_1_4 = {5f 24 24 24 24 24 24 00 2e 63 6d 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "POST /photos/photo.asp HTTP/1.1" ascii //weight: 1
        $x_1_6 = {25 77 69 6e 64 69 72 25 5c 74 65 6d 70 5c 63 6f 6e 69 6d 65 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Derusbi_D_2147691852_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Derusbi.D!dha"
        threat_id = "2147691852"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PCC_CMD" ascii //weight: 1
        $x_1_2 = "PCC_PROXY" ascii //weight: 1
        $x_1_3 = "PCC_BASE" ascii //weight: 1
        $x_1_4 = "ZhuDongFangYu.exe" wide //weight: 1
        $x_1_5 = "rundll32.exe \"%s\", R32 %s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Derusbi_E_2147691853_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Derusbi.E!dha"
        threat_id = "2147691853"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PCC_CMD" ascii //weight: 1
        $x_1_2 = "GET /Photos/Query.cgi?loginid=" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_4 = "ZhuDongFangYu.exe" wide //weight: 1
        $x_1_5 = "AE2A3887-A30A-4B39-A5E6-AC891A07AFF" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Derusbi_G_2147691854_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Derusbi.G!dha"
        threat_id = "2147691854"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/solutions/company-size/smb/index.htm" ascii //weight: 1
        $x_1_2 = "/selfservice/microsites/search.php" ascii //weight: 1
        $x_1_3 = "rundll32.exe \"%s\",NlaNotEqual" ascii //weight: 1
        $x_1_4 = "E190BC79-02DC-0166-4CF1-BD8F8CB2FF21" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Derusbi_H_2147691855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Derusbi.H!dha"
        threat_id = "2147691855"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Derusbi"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PCC_MISC" ascii //weight: 1
        $x_1_2 = "PCC_MEDIA" ascii //weight: 1
        $x_1_3 = "EA-7114" ascii //weight: 1
        $x_1_4 = ".blankchair.com:443" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

