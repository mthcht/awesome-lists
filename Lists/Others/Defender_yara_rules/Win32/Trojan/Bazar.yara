rule Trojan_Win32_Bazar_GA_2147778872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bazar.GA!MTB"
        threat_id = "2147778872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\" ascii //weight: 1
        $x_1_2 = "POST %s HTTP/1.1" ascii //weight: 1
        $x_1_3 = "Host: %s" ascii //weight: 1
        $x_1_4 = "Pragma: no-cache" ascii //weight: 1
        $x_1_5 = "Content-Length: %d" ascii //weight: 1
        $x_1_6 = "http://call2.xyz/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

