rule HackTool_Win32_Mailpassview_2147571412_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mailpassview"
        threat_id = "2147571412"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mailpassview"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PasswordFox.exe" wide //weight: 5
        $x_5_2 = "VNCPassView.exe" wide //weight: 5
        $x_5_3 = "BulletsPassView.exe" wide //weight: 5
        $x_1_4 = "Password Field" wide //weight: 1
        $x_1_5 = "Password Type" wide //weight: 1
        $x_1_6 = "Passwords List" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_Mailpassview_2147571412_1
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mailpassview"
        threat_id = "2147571412"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mailpassview"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mailpv.pdb" ascii //weight: 10
        $x_10_2 = "www.nirsoft.net" ascii //weight: 10
        $x_1_3 = "Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts" ascii //weight: 1
        $x_1_4 = "Password.NET Messenger Service" ascii //weight: 1
        $x_1_5 = "SELECT id, hostname, httpRealm, formSubmitURL, usernameField, passwordField, encryptedUsername, encryptedPass" ascii //weight: 1
        $x_1_6 = "KeePass csv file" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

