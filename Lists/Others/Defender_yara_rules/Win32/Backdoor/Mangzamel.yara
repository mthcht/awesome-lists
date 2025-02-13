rule Backdoor_Win32_Mangzamel_A_2147725625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mangzamel.A!dha"
        threat_id = "2147725625"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mangzamel"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {85 c0 74 3c 3d e5 03 00 00 74 35 3d 33 27 00 00 74 2e}  //weight: 3, accuracy: High
        $x_3_2 = {c7 44 24 18 07 51 10 33 c7 44 24 20 00 00 00 00 e8 ?? ?? ff ff 8b 86 94 00 00 00 50 e8 ?? ?? ff ff 8b 16 83 c4 04 8b ce c7 86 94 00 00 00 00 00 00 00 68 01 51 10 33 ff 52 14}  //weight: 3, accuracy: Low
        $x_2_3 = "ewr:m:s:h:p:t:b:d:n:w:x:g:k:" ascii //weight: 2
        $x_1_4 = "Mang.xml" ascii //weight: 1
        $x_1_5 = "mangsrv" ascii //weight: 1
        $x_1_6 = "Dcom Service Checker Service" ascii //weight: 1
        $x_1_7 = "\\Hotfix\\Q246009" ascii //weight: 1
        $x_1_8 = "LDSUpDvr" ascii //weight: 1
        $x_1_9 = "CFGEXTR" ascii //weight: 1
        $x_1_10 = "CFG2EXTR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

