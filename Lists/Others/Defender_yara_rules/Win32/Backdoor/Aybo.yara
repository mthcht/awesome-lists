rule Backdoor_Win32_Aybo_B_2147721705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Aybo.B"
        threat_id = "2147721705"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Aybo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SCHTASKS /Create /TN RegUpdate /SC onstart" ascii //weight: 1
        $x_1_2 = "tmpdrv.exe" ascii //weight: 1
        $x_1_3 = "Ayabot" ascii //weight: 1
        $x_1_4 = "classes/s.php" ascii //weight: 1
        $x_1_5 = "0942c3aad278ce5ea571a61712b4506a.php" ascii //weight: 1
        $x_1_6 = "add rule name=\"Security Fix\" protocol=TCP dir=in localport=445 action=block" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

