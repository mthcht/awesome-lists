rule Trojan_Win32_Leeson_A_2147811731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Leeson.A!dha"
        threat_id = "2147811731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Leeson"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "f$$$%s&&&%s&&&%s&&&%d&&&%ld&&&%s" ascii //weight: 1
        $x_1_2 = "MrOmAkqto26rQkY7nZKd6g==" ascii //weight: 1
        $x_1_3 = "b$$$%s&&&%d&&&%d&&&" ascii //weight: 1
        $x_1_4 = "w([a-zA-Z]+)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

