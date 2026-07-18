rule Trojan_Win32_Sock5Systemz_LR_2147973736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sock5Systemz.LR!MTB"
        threat_id = "2147973736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sock5Systemz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8d 14 38 8b ca 8d 41 01 89 45 f0 8a 01 41 84 c0 75 ?? 2b 4d f0 51}  //weight: 20, accuracy: Low
        $x_10_2 = {83 f8 7a 75 ?? 39 75 fc 77 ?? 81 ce ff 0f 00 00 46 89 75 fc}  //weight: 10, accuracy: Low
        $x_3_3 = "\\boost_1_55_0\\staging\\include\\boost-1_55\\boost/exception/detail/exception_ptr" ascii //weight: 3
        $x_2_4 = "\\\\.\\PhysicalDrive0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

