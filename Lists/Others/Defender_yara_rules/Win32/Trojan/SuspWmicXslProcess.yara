rule Trojan_Win32_SuspWmicXslProcess_A_2147967375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmicXslProcess.A"
        threat_id = "2147967375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmicXslProcess"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "/format:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

