rule Backdoor_Win32_Imecab_A_2147728372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Imecab.A"
        threat_id = "2147728372"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Imecab"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net localgroup administrators guest /add" ascii //weight: 1
        $x_1_2 = "SeDenyRemoteInteractiveLogonRight =  >> c:\\test.inf" ascii //weight: 1
        $x_1_3 = "SECEDIT /CONFIGURE /CFG c:\\test.inf /DB dummy.sdb" ascii //weight: 1
        $x_1_4 = "net localgroup guests guest /del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

