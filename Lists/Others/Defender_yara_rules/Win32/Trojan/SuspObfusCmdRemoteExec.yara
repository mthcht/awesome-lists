rule Trojan_Win32_SuspObfusCmdRemoteExec_A_2147980268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspObfusCmdRemoteExec.A"
        threat_id = "2147980268"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspObfusCmdRemoteExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cu^r^l" wide //weight: 1
        $x_1_2 = "c^m^d" wide //weight: 1
        $x_1_3 = "h^t^t^p" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

