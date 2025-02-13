rule Trojan_Win32_Iniriror_A_2147612798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iniriror.A!dll"
        threat_id = "2147612798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iniriror"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "57"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SRAT.dll" ascii //weight: 20
        $x_3_2 = ".klg" ascii //weight: 3
        $x_3_3 = "127.0.0.1" ascii //weight: 3
        $x_3_4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0; MyIE 3.01)" ascii //weight: 3
        $x_3_5 = "TWebCamThread" ascii //weight: 3
        $x_3_6 = "No Shares Found" ascii //weight: 3
        $x_1_7 = "CaptureWindow" ascii //weight: 1
        $x_1_8 = "ICSendMessage" ascii //weight: 1
        $x_1_9 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_10 = "\\\\.\\SMARTVSD" ascii //weight: 1
        $x_1_11 = "Referer: http://" ascii //weight: 1
        $x_20_12 = {40 99 89 45 e0 89 55 e4 c7 45 e8 bb bb bb bb c7 45 ec aa aa aa aa 8d 55 e0 b9 10 00 00 00 8b c6}  //weight: 20, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 4 of ($x_3_*) and 5 of ($x_1_*))) or
            ((2 of ($x_20_*) and 5 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

