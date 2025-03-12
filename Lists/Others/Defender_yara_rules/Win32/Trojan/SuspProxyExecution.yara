rule Trojan_Win32_SuspProxyExecution_A_2147935888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.A"
        threat_id = "2147935888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "regasm.exe" ascii //weight: 1
        $x_1_2 = "regsvc.exe" ascii //weight: 1
        $x_2_3 = {2f 00 74 00 6c 00 62 00 3a 00 [0-200] 2e 00 74 00 6c 00 62 00}  //weight: 2, accuracy: Low
        $x_2_4 = {2f 74 6c 62 3a [0-200] 2e 74 6c 62}  //weight: 2, accuracy: Low
        $x_2_5 = "_component.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

