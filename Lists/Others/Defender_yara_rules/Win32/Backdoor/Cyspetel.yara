rule Backdoor_Win32_Cyspetel_A_2147642412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Cyspetel.A"
        threat_id = "2147642412"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Cyspetel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "srvstop=\"1\"&" wide //weight: 3
        $x_3_2 = "Status updated for pending 30 sec" wide //weight: 3
        $x_3_3 = "c:\\svcex.log" wide //weight: 3
        $x_3_4 = "[ureg]=\"1\"&" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

