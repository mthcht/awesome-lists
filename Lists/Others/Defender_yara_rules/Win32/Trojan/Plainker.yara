rule Trojan_Win32_Plainker_A_2147765459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plainker.A!dha"
        threat_id = "2147765459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plainker"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Kevin\\Projects\\Mat NewSource\\" ascii //weight: 2
        $x_2_2 = "9e9a6754-3c5f-6786-b6fe-da94c7ece7ba" ascii //weight: 2
        $x_2_3 = "cmd /c nslookup -retry=2 -type=" ascii //weight: 2
        $x_1_4 = "create_directory(p): invalid argument" ascii //weight: 1
        $x_1_5 = "/helper.ini" ascii //weight: 1
        $x_1_6 = ",address= %s, msg= %s" ascii //weight: 1
        $x_1_7 = "ipconfig /flushdns & exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Plainker_B_2147765460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plainker.B!dha"
        threat_id = "2147765460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plainker"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sysadminnews.info" ascii //weight: 2
        $x_2_2 = "windowsupdatecdn.com" ascii //weight: 2
        $x_2_3 = "\\BackDorLast\\" ascii //weight: 2
        $x_2_4 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & del /f /q" ascii //weight: 2
        $x_2_5 = "{%08x-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}" ascii //weight: 2
        $x_1_6 = "prxadr=" ascii //weight: 1
        $x_1_7 = "-myfile--" ascii //weight: 1
        $x_1_8 = "Default.aspx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

