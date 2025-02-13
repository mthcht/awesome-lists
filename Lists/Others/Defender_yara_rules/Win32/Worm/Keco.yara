rule Worm_Win32_Keco_A_2147504940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Keco.A"
        threat_id = "2147504940"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Keco"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "HELO .com" ascii //weight: 10
        $x_10_2 = "mx1.hotmail.com" ascii //weight: 10
        $x_10_3 = "Content-Transfer-Encoding: base64" ascii //weight: 10
        $x_10_4 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_1_5 = "--ShutFace--" ascii //weight: 1
        $x_1_6 = "--VXrulez--" ascii //weight: 1
        $x_1_7 = "Stfu@Abuse.com" ascii //weight: 1
        $x_1_8 = ".dcc send $nick" ascii //weight: 1
        $x_1_9 = "\\C$\\AutoExec.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

