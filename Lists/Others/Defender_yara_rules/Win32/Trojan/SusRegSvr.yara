rule Trojan_Win32_SusRegSvr_MK_2147945912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegSvr.MK"
        threat_id = "2147945912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegSvr"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "regsvr32.exe /u /s" wide //weight: 1
        $x_1_2 = "phonehome" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

