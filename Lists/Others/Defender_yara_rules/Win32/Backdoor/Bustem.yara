rule Backdoor_Win32_Bustem_A_2147650466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Bustem.A"
        threat_id = "2147650466"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Bustem"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "params\":[],\"method\":\"getwork\",\"id\":\"json" ascii //weight: 1
        $x_1_2 = "sock created: %d (%d:%d:%d)" ascii //weight: 1
        $x_1_3 = "user:password" ascii //weight: 1
        $x_1_4 = "109.230.246.66" ascii //weight: 1
        $x_1_5 = "109.230.217.13" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

