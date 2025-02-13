rule Trojan_Win32_Dumaru_2147555609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dumaru"
        threat_id = "2147555609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dumaru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "199.166.6.2" ascii //weight: 2
        $x_1_2 = "*** Protected Storage Data ***" ascii //weight: 1
        $x_1_3 = "*** Protected Storage Data ends ***" ascii //weight: 1
        $x_2_4 = "<address@yandex.ru>" ascii //weight: 2
        $x_1_5 = "===KEYLOGGER DATA END===" ascii //weight: 1
        $x_1_6 = "===KEYLOGGER DATA START===" ascii //weight: 1
        $x_1_7 = "\\rundllx.sys" ascii //weight: 1
        $x_1_8 = "\\rundlln.sys" ascii //weight: 1
        $x_1_9 = "\\vxdload.log" ascii //weight: 1
        $x_1_10 = "\\TEMP\\1.eml" ascii //weight: 1
        $x_2_11 = "C:\\WINDOWS\\SYSTEM\\load32.exe" ascii //weight: 2
        $x_2_12 = "explorer.exe C:\\WINDOWS\\SYSTEM\\vxdmgr32.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

