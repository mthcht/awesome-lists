rule Ransom_Win32_Hatecrypt_2147725276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Hatecrypt"
        threat_id = "2147725276"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Hatecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "death.bat\" del \"C:\\TEMP\\afolder\\death.bat\"" ascii //weight: 2
        $x_2_2 = "deathnote.bat\" del \"C:\\TEMP\\afolder\\deathnote.bat\"" ascii //weight: 2
        $x_2_3 = "WIFI-CONNECT.bat\" del \"C:\\TEMP\\afolder\\WIFI-CONNECT.bat\"" ascii //weight: 2
        $x_2_4 = "windows defender.bat\" del \"C:\\TEMP\\afolder\\windows defender.bat\"" ascii //weight: 2
        $x_2_5 = "WIFI.lnk\" del \"C:\\TEMP\\afolder\\WIFI.lnk\"" ascii //weight: 2
        $x_2_6 = "WINDEFEND.lnk\" del \"C:\\TEMP\\afolder\\WINDEFEND.lnk\"" ascii //weight: 2
        $x_2_7 = "death.lnk\" del \"C:\\TEMP\\afolder\\death.lnk\"" ascii //weight: 2
        $x_2_8 = "deathnote.lnk\" del \"C:\\TEMP\\afolder\\deathnote.lnk\"" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

