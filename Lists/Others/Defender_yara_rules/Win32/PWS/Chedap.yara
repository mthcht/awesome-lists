rule PWS_Win32_Chedap_A_2147653580_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Chedap.A"
        threat_id = "2147653580"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Chedap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 0a 8a 1a 98 69 9f 55}  //weight: 1, accuracy: High
        $x_1_2 = "%s?act=add&user=%s&pwd=%s&ll1=%s&ll2=%d&ll3=%s" ascii //weight: 1
        $x_1_3 = "65904321" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

