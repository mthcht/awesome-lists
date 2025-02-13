rule Backdoor_Win32_Teldoor_C_2147630830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Teldoor.C"
        threat_id = "2147630830"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Teldoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tlntadmn config port=972 sec=-NTLM" ascii //weight: 1
        $x_1_2 = "net start Telnet" ascii //weight: 1
        $x_1_3 = "sc config tlntsvr start= auto" ascii //weight: 1
        $x_1_4 = "SUPPORT_388945a0 /del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

