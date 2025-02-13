rule TrojanProxy_Win32_Dlena_2147583146_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Dlena"
        threat_id = "2147583146"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlena"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh firewall set allowedprogram %s enable" ascii //weight: 1
        $x_1_2 = "http://windowsupdate.microsoft.com/" ascii //weight: 1
        $x_1_3 = "currentsystemhAnDleR" ascii //weight: 1
        $x_1_4 = "to MX (err #%i)" ascii //weight: 1
        $x_1_5 = "\\CurrentVersion\\WinOpt" ascii //weight: 1
        $x_1_6 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_7 = "#32770" ascii //weight: 1
        $x_1_8 = "\\%i%i%i2ld.exe" ascii //weight: 1
        $x_1_9 = "208.66.194.9" ascii //weight: 1
        $x_1_10 = "%RND_HEX" ascii //weight: 1
        $x_1_11 = "%RND_NUM" ascii //weight: 1
        $x_1_12 = "%RND_DIGIT" ascii //weight: 1
        $x_1_13 = "no mailbox here" ascii //weight: 1
        $x_1_14 = {d1 27 d1 47 04 d1 57 08 d1 57 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

