rule Trojan_Win32_Hichaol_2147645717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hichaol"
        threat_id = "2147645717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hichaol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?action=aolsbm&mode=res&v=1&status=%d&id=%s&hardid=%s" ascii //weight: 1
        $x_1_2 = "ERROR: no task id" ascii //weight: 1
        $x_1_3 = "saved id doesn't match task" ascii //weight: 1
        $x_1_4 = "Aol submit start" ascii //weight: 1
        $x_1_5 = "hash check failed" ascii //weight: 1
        $x_1_6 = "hGhdy6s" ascii //weight: 1
        $x_1_7 = "crypted code detected" ascii //weight: 1
        $x_1_8 = "#BLUELABEL" ascii //weight: 1
        $x_1_9 = "Main domain is not responding" ascii //weight: 1
        $x_1_10 = "dump responce" ascii //weight: 1
        $x_1_11 = "%skLa%s" ascii //weight: 1
        $x_1_12 = "#BlAc" ascii //weight: 1
        $x_1_13 = "parse responce" ascii //weight: 1
        $x_1_14 = "%s?action=%s&v=1&hardid=%s&id=%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

