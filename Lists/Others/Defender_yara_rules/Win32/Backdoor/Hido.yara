rule Backdoor_Win32_Hido_A_2147604741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Hido.gen!A"
        threat_id = "2147604741"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Hido"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "protectorservice" ascii //weight: 2
        $x_2_2 = "protector.sys" ascii //weight: 2
        $x_2_3 = "NtCreateSection" ascii //weight: 2
        $x_2_4 = "\\\\.\\PROTECTOR" ascii //weight: 2
        $x_2_5 = "WINDOWS\\system32\\regsvr32.exe" ascii //weight: 2
        $x_2_6 = "WINDOWS\\system32\\sc.exe" ascii //weight: 2
        $x_2_7 = "easyclickplus9" ascii //weight: 2
        $x_2_8 = "Explorer_TridentDlgFrame" ascii //weight: 2
        $x_2_9 = "CWebBrowser2" ascii //weight: 2
        $x_2_10 = "60.190.223.11" ascii //weight: 2
        $x_2_11 = "219.232.224.126" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

