rule Trojan_Win32_Kangker_A_2147620039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kangker.A"
        threat_id = "2147620039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kangker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SMSSISRUNNING" ascii //weight: 1
        $x_1_2 = "baidu.com/index" ascii //weight: 1
        $x_1_3 = "avp.txt" ascii //weight: 1
        $x_1_4 = "http://%77%77%77%2E%6B%61%6E%67%6B%2E%63%6E/%74%65%6D%70%2E%68%74%6D%6C" ascii //weight: 1
        $x_1_5 = "SeShutdownPrivilege" ascii //weight: 1
        $x_1_6 = "Software\\Policies\\Microsoft\\MMC\\{58221C66-EA27-11CF-ADCF-00AA00A80033}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

