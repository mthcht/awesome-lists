rule PWS_Win32_Pebox_A_2147626132_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Pebox.A"
        threat_id = "2147626132"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pebox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "suser=%s&spass=%s&serial=%s&serNum" ascii //weight: 5
        $x_5_2 = "suser=%s&spass=%s&level=%d&sname=%s&money" ascii //weight: 5
        $x_1_3 = "c:\\pass.log" ascii //weight: 1
        $x_1_4 = "&Usertting.ini" ascii //weight: 1
        $x_1_5 = "UserSetting.ini" ascii //weight: 1
        $x_1_6 = "LastSelectName" ascii //weight: 1
        $x_1_7 = "TenQQAccount.dll" ascii //weight: 1
        $x_1_8 = "KICK" ascii //weight: 1
        $x_1_9 = "DISPLAY" ascii //weight: 1
        $x_1_10 = "Hatanem.dat" ascii //weight: 1
        $x_1_11 = "c:\\recv.log" ascii //weight: 1
        $x_1_12 = "c:\\send.log" ascii //weight: 1
        $x_1_13 = "QqAccount.dll" ascii //weight: 1
        $x_1_14 = "makesurethismymail" ascii //weight: 1
        $x_1_15 = "uploadaimgfile" ascii //weight: 1
        $x_1_16 = "safecode:" ascii //weight: 1
        $x_1_17 = "data\\config.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

