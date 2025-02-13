rule TrojanSpy_Win32_Dobestel_A_2147688424_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Dobestel.A"
        threat_id = "2147688424"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dobestel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HaveCommand" ascii //weight: 1
        $x_1_2 = "Cmd_dl" ascii //weight: 1
        $x_1_3 = "Cmd_upld" ascii //weight: 1
        $x_1_4 = "Cmd_rmv" ascii //weight: 1
        $x_1_5 = "Cmd_com" ascii //weight: 1
        $x_1_6 = "Cmd_updt" ascii //weight: 1
        $x_1_7 = "Cmd_Exe" ascii //weight: 1
        $x_1_8 = "SELECT username_value, password_value, signon_realm FROM logins" ascii //weight: 1
        $x_1_9 = "SELECT hostname, encryptedUsername, encryptedPassword, encType From moz_logins" ascii //weight: 1
        $x_1_10 = "\\{AA55FF5544DD11AA11}\\" wide //weight: 1
        $x_1_11 = "01AA1F54BCb343e5bfdabc054ab45d67.tmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

