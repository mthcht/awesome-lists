rule Trojan_Win32_SystemBinaryProxyMavinjectExec_A_2147951149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SystemBinaryProxyMavinjectExec.A"
        threat_id = "2147951149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemBinaryProxyMavinjectExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mavinject" wide //weight: 1
        $x_1_2 = " /injectrunning " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

