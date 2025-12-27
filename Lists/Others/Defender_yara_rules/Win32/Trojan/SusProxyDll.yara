rule Trojan_Win32_SusProxyDll_MK_2147947973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxyDll.MK"
        threat_id = "2147947973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxyDll"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32" ascii //weight: 1
        $x_1_2 = "phonehome_main " ascii //weight: 1
        $x_1_3 = "phoneHome" ascii //weight: 1
        $x_1_4 = "\\\\.\\pipe\\move" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

