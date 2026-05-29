rule Trojan_Win32_SusWmicXslProcessing_MK_2147970494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmicXslProcessing.MK"
        threat_id = "2147970494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmicXslProcessing"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "/format:" wide //weight: 1
        $n_1_3 = "l4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce6" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

