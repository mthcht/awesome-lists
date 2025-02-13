rule Trojan_Win32_Aydamine_A_2147721706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Aydamine.A"
        threat_id = "2147721706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Aydamine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sys-Mutex2" ascii //weight: 1
        $x_1_2 = "\\registration\\reg.cnf" ascii //weight: 1
        $x_1_3 = "\\SysData\\acnom.exe" ascii //weight: 1
        $x_1_4 = "\\SysData\\acnon.exe" ascii //weight: 1
        $x_1_5 = "-c 1 -M stratum+tcp://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

