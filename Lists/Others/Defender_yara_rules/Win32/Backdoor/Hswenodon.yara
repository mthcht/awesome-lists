rule Backdoor_Win32_Hswenodon_A_2147721088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hswenodon.A"
        threat_id = "2147721088"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hswenodon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "supernode_con.dll" ascii //weight: 1
        $x_1_2 = "%s\\rr.bat" ascii //weight: 1
        $x_1_3 = "ping -n 5 127.0.0.1" ascii //weight: 1
        $x_2_4 = "%s\\rundll32.exe \"%s\",HwmonServerMain" ascii //weight: 2
        $x_1_5 = "net start %s" ascii //weight: 1
        $x_1_6 = "Server: nginx/1.9.12" ascii //weight: 1
        $x_1_7 = "HwmonWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

