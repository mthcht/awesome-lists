rule HackTool_Win32_PassDump_A_2147720183_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PassDump.A!dha"
        threat_id = "2147720183"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PassDump"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS" ascii //weight: 1
        $x_1_2 = "\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_3 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" ascii //weight: 1
        $x_1_4 = ".\\PAI\\IEforXPpasswords.txt" ascii //weight: 1
        $x_1_5 = "Windows 8 - 10 IE credentials" wide //weight: 1
        $x_1_6 = "Can not copy Wand File" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

