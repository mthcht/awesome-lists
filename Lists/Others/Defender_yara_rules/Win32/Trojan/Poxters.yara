rule Trojan_Win32_Poxters_AMTB_2147966339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poxters!AMTB"
        threat_id = "2147966339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poxters"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Resilience Software" ascii //weight: 1
        $x_1_2 = "*********.com" ascii //weight: 1
        $x_2_3 = "\\Desktop\\POSGrabber_mutated.exe" ascii //weight: 2
        $x_1_4 = "\\Application Data\\iorti\\iorti.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

