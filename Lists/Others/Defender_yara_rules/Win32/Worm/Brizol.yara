rule Worm_Win32_Brizol_2147596498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brizol"
        threat_id = "2147596498"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brizol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MAIL FROM: <%s>" ascii //weight: 1
        $x_1_2 = "RCPT TO: <%s>" ascii //weight: 1
        $x_1_3 = "\\scansvc\\trust" ascii //weight: 1
        $x_1_4 = "@blackhotmail.com" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Internet Account Manager\\Accounts\\%s" ascii //weight: 1
        $x_1_6 = "\\officeparam.dll" ascii //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_8 = "MODEM" ascii //weight: 1
        $x_1_9 = {2e 4e 45 54 00 00 00 00 2e 6e 65 74 00 00 00 00 2e 43 4f 4d 00 00 00 00 2e 63 6f 6d 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

