rule Trojan_Win32_Lenoplug_A_2147727685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lenoplug.A"
        threat_id = "2147727685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lenoplug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\LenovoServicePlugin.dmp" ascii //weight: 1
        $x_1_2 = "sc config LenovoServicePluginSvc start= auto" ascii //weight: 1
        $x_1_3 = "net start LenovoServicePluginSvc" ascii //weight: 1
        $x_1_4 = "REG ADD HKEY_CLASSES_ROOT\\LenovoServicePlugin\\shell\\open\\command /v \"\" /t REG_SZ /d \"\\\"C:\\ProgramData\\LenovoIhd\\LenovoServicePlugin.exe\\\" \\\"%1\\\"\"  /f" ascii //weight: 1
        $x_2_5 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 4c 00 65 00 6e 00 6f 00 76 00 6f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 50 00 6c 00 75 00 67 00 69 00 6e 00 4d 00 61 00 69 00 6e 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

