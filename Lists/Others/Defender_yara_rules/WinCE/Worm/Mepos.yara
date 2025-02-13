rule Worm_WinCE_Mepos_A_2147602178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:WinCE/Mepos.A"
        threat_id = "2147602178"
        type = "Worm"
        platform = "WinCE: Windows CE platform"
        family = "Mepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f e0 a0 11 05 f0 a0 11 37 3c e0 e3 f3 30 23 e2 00 40 93 e5 ?? ?? ?? ?? 00 00 54 e1 40 00 9f 15 00 e0 a0 13 00 30 a0 13 00 20 a0 13 00 10 a0 13 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 55 e3 ?? ?? 9d 05 ?? ?? 9d 05 ?? ?? ?? ?? 06 10 a0 e1 42 00 a0 e3 ?? ?? ?? ?? 00 00 e0 e3}  //weight: 4, accuracy: Low
        $x_2_2 = "http://mobi.xiaomeiti.com/uploadfile/mservice2.zip" ascii //weight: 2
        $x_2_3 = "%s?imei=%s&MajorVersion=%d&MinorVersion=%d&BuildNumber=%d&Width=%d&Hight=%d&TotalPhys=%d&UILanguage=%d&LangID=%d&model=%s&platform=%s" ascii //weight: 2
        $x_2_4 = "http://mobi.xiaomeiti.com/updateimei" ascii //weight: 2
        $x_2_5 = "%s?mv=%d&imsi=%s&imei=%s&build=%d&type=%d&owner=%s" ascii //weight: 2
        $x_1_6 = "\\Windows\\mss.zip" ascii //weight: 1
        $x_1_7 = "InternetReadFile" ascii //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "\\%s\\2577\\autorun.exe" ascii //weight: 1
        $x_1_10 = "\\Security\\Policies\\Policies" ascii //weight: 1
        $x_1_11 = "\\\\.\\Notifications\\NamedEvents\\AppRunAtNetConnect" ascii //weight: 1
        $x_1_12 = "IPM.SMStext" ascii //weight: 1
        $x_1_13 = "GPRS Device Finder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

