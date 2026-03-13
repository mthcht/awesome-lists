rule Trojan_Win64_BoryptGrabStealer_AMTB_2147964718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BoryptGrabStealer!AMTB"
        threat_id = "2147964718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BoryptGrabStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://45.93.20.61:5466/api/" ascii //weight: 3
        $x_1_2 = "powershell.exe" ascii //weight: 1
        $x_1_3 = "-WindowStyle Hidden" ascii //weight: 1
        $x_1_4 = "-ExecutionPolicy Bypass" ascii //weight: 1
        $x_1_5 = "-Command \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

