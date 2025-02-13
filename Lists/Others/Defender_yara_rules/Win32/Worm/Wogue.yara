rule Worm_Win32_Wogue_A_2147598171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wogue.A"
        threat_id = "2147598171"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wogue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://webye163.cn/hz" ascii //weight: 10
        $x_10_2 = "shellexecute=IO.pif" ascii //weight: 10
        $x_1_3 = "Net Stop Norton Antivirus Auto Protect Service" ascii //weight: 1
        $x_1_4 = "Net Stop mcshield" ascii //weight: 1
        $x_1_5 = "net stop \"Windows Firewall/Internet Connection Sharing (ICS)\"" ascii //weight: 1
        $x_1_6 = "net stop System Restore Service" ascii //weight: 1
        $x_10_7 = "DirectX10.dll" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Wogue_C_2147615996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wogue.C"
        threat_id = "2147615996"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wogue"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d [0-8] 2e 70 69 66}  //weight: 10, accuracy: Low
        $x_10_2 = ":\\autorun.inf" ascii //weight: 10
        $x_5_3 = {44 69 72 65 63 74 58 [0-2] 2e 64 6c 6c}  //weight: 5, accuracy: Low
        $x_1_4 = "Net Stop Norton Antivirus Auto Protect Service" ascii //weight: 1
        $x_1_5 = "Net Stop mcshield" ascii //weight: 1
        $x_1_6 = "net stop \"Windows Firewall/Internet Connection Sharing (ICS)\"" ascii //weight: 1
        $x_1_7 = "net stop System Restore Service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

