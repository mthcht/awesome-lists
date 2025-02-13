rule Backdoor_Win32_Kyrdor_F_2147595006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Kyrdor.F"
        threat_id = "2147595006"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Kyrdor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "39"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c [0-8] 2e 64 6c 6c}  //weight: 10, accuracy: Low
        $x_10_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad" ascii //weight: 10
        $x_5_4 = "WinExec" ascii //weight: 5
        $x_2_5 = "phfkt.dll" ascii //weight: 2
        $x_2_6 = "dofckt.dll" ascii //weight: 2
        $x_1_7 = "rdshost.dll" ascii //weight: 1
        $x_1_8 = "rdshost2.dll" ascii //weight: 1
        $x_1_9 = "rdssrv.exe" ascii //weight: 1
        $x_1_10 = "rdssrv2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

