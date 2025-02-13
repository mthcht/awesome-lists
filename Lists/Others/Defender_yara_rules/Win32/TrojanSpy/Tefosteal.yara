rule TrojanSpy_Win32_Tefosteal_A_2147734159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tefosteal.A"
        threat_id = "2147734159"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tefosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files\\InfoPC.txt" wide //weight: 1
        $x_1_2 = "\\Files\\BSSID.txt" wide //weight: 1
        $x_1_3 = "\\Files\\Discord\\Local Storage" wide //weight: 1
        $x_1_4 = "PasswordRecoveryChrome.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Tefosteal_B_2147734160_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tefosteal.B"
        threat_id = "2147734160"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tefosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\Files\\InfoPC\\Systeminfo.txt" wide //weight: 5
        $x_5_2 = "\\Files\\InfoPC\\System_Info.txt" wide //weight: 5
        $x_1_3 = "\\Files\\InfoPC\\BSSID.txt" wide //weight: 1
        $x_1_4 = "\\Files\\Discord\\Local Storage\\" wide //weight: 1
        $x_1_5 = "PasswordRecoveryChrome.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Tefosteal_C_2147734161_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tefosteal.C"
        threat_id = "2147734161"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tefosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svnhost.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Tefosteal_D_2147734162_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Tefosteal.D"
        threat_id = "2147734162"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Tefosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Files\\InfoPC.txt" wide //weight: 1
        $x_5_2 = "\\infopc.vbs" wide //weight: 5
        $x_5_3 = "\\inform.vbs" wide //weight: 5
        $x_5_4 = "\\findip.vbs" wide //weight: 5
        $x_5_5 = "\\asearch.vbs" wide //weight: 5
        $x_1_6 = "\\Files\\Discord\\Local Storage" wide //weight: 1
        $x_1_7 = "PasswordRecoveryChrome.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

