rule Trojan_Win32_Crosdomd_MKV_2147966414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crosdomd.MKV!MTB"
        threat_id = "2147966414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crosdomd"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidden" wide //weight: 1
        $x_1_2 = "bypass" wide //weight: 1
        $x_1_3 = "Temp" wide //weight: 1
        $x_2_4 = "http:" wide //weight: 2
        $x_5_5 = "sfrclak.com" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

