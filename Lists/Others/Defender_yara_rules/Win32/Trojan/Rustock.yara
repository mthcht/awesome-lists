rule Trojan_Win32_Rustock_C_137390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rustock.C"
        threat_id = "137390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 78 40 04 73 1a b8 ?? ?? 41 00 e8 ?? ?? ff ff 6a 00 6a 06 e8 ?? ?? fe ff 6a ff e8 ?? ?? fe ff}  //weight: 1, accuracy: Low
        $x_1_2 = "Portions Copyright (c) 1999,2003 Avenger by NhT" ascii //weight: 1
        $x_1_3 = "system\\CurrentControlSet\\Services\\" ascii //weight: 1
        $x_1_4 = "208.66.194.215" ascii //weight: 1
        $x_1_5 = "olga-rent-a-car.info" ascii //weight: 1
        $x_1_6 = "gmail.com" ascii //weight: 1
        $x_1_7 = "yahoo.com" ascii //weight: 1
        $x_1_8 = "siwsym.sys" ascii //weight: 1
        $x_1_9 = "syser.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

