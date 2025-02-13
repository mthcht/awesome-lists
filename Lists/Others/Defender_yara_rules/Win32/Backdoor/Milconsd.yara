rule Backdoor_Win32_Milconsd_A_2147683879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Milconsd.A"
        threat_id = "2147683879"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Milconsd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "This machine Has been into Mil !!!!" ascii //weight: 10
        $x_1_2 = "StartSniffer" ascii //weight: 1
        $x_1_3 = "StartUsbSteal" ascii //weight: 1
        $x_1_4 = "DownRun URL_1:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

