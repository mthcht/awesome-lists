rule Worm_Win32_Namepuk_A_2147723694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Namepuk.A"
        threat_id = "2147723694"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Namepuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileCopy \"[PubDir][pubnamehk].exe\" \"[drvltr][pubnamehk].exe\"" ascii //weight: 1
        $x_1_2 = "[UserName]-[Year][MonthNum][DayNum][Hour][Minute][Second].jpg" ascii //weight: 1
        $x_1_3 = "FileExists \"C:\\Documents and Settings\\All Users\\Start Menu\\Programs\\Startup\\[pubnamehk].exe\" \"[startupcheck]\"" ascii //weight: 1
        $x_1_4 = "SetVar \"[drvltr]\" \"Z:\\\"" ascii //weight: 1
        $x_1_5 = "FileWrite \"[drvltr]autorun.inf\" \"8\" \"shell\\openin\\command=[pubnamehk].exe\"" ascii //weight: 1
        $x_1_6 = "FileCopy \"[PubDir][pubnamehk].exe\" \"[drvltr][gendirlistitem]\\[gendirlistitem].exe\"" ascii //weight: 1
        $x_1_7 = "FileExists \"[dirpath]\\[dirpathgendirlistitem]\\[dirpathgendirlistitem].exe\" \"[dirpathgendirlistitemx]\"" ascii //weight: 1
        $x_1_8 = "GoSub \"drvscn\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

