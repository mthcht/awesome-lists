rule Worm_Win32_Wowstealer_A_2147576398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wowstealer.A"
        threat_id = "2147576398"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wowstealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "game4enjoy" ascii //weight: 1
        $x_1_2 = "AddSelfLinkToHtml" ascii //weight: 1
        $x_1_3 = "html_execute" ascii //weight: 1
        $x_1_4 = "iframe src=\"http://www." ascii //weight: 1
        $x_1_5 = "Internet Account Manager\\Accounts\\" ascii //weight: 1
        $x_1_6 = "Microsoft\\OutLook Express\\" ascii //weight: 1
        $x_1_7 = "MAPISendMail" ascii //weight: 1
        $x_1_8 = "MAPI32.DLL" ascii //weight: 1
        $x_1_9 = "SMTP: %s" ascii //weight: 1
        $x_1_10 = "MAILBODY" ascii //weight: 1
        $x_1_11 = "/Data.asp" ascii //weight: 1
        $x_1_12 = "&text=" ascii //weight: 1
        $x_1_13 = "datatype=mailaddr" ascii //weight: 1
        $x_1_14 = "[%s=%s]" ascii //weight: 1
        $x_1_15 = "#32770" ascii //weight: 1
        $x_1_16 = "Outlook Express" ascii //weight: 1
        $x_1_17 = "wow.exe" ascii //weight: 1
        $x_1_18 = "srv_%d_.log" ascii //weight: 1
        $x_1_19 = "ZIPEXE" ascii //weight: 1
        $x_1_20 = "Zip.Exe" ascii //weight: 1
        $x_1_21 = "patch.exe" ascii //weight: 1
        $x_1_22 = "AREA=%s" ascii //weight: 1
        $x_1_23 = "PASSWORD=%s" ascii //weight: 1
        $x_1_24 = "ACCOUNT=%s" ascii //weight: 1
        $x_1_25 = "[WOW]" ascii //weight: 1
        $x_1_26 = "datatype=wow" ascii //weight: 1
        $x_1_27 = "GxWindowClassD3d" ascii //weight: 1
        $x_1_28 = "World of Warcraft" ascii //weight: 1
        $x_1_29 = "Blizzard Entertainment,pls kindly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (24 of ($x*))
}

