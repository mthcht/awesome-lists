rule Trojan_Win32_Dnoper_ND_2147903936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dnoper.ND!MTB"
        threat_id = "2147903936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dnoper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rWimLgZuUuPUpshWKcQIOf5MzBMnFM5fGOoAqJN3ZJ.bat" ascii //weight: 1
        $x_1_2 = "AqJN3ZJ.bat" ascii //weight: 1
        $x_1_3 = "PyJfpR3WP.vbe" ascii //weight: 1
        $x_1_4 = "rokerDllSvc.exe" ascii //weight: 1
        $x_1_5 = "BrokerDllSvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

