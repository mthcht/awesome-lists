rule HackTool_Win32_HeuKmsActivator_2147973407_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/HeuKmsActivator"
        threat_id = "2147973407"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "HeuKmsActivator"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 65 00 75 00 5f 00 6b 00 6d 00 73 00 5f 00 61 00 63 00 74 00 69 00 76 00 61 00 74 00 6f 00 72 00 5f 00 76 00 [0-8] 2e 00 [0-8] 2e 00 [0-14] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $n_10_2 = "Quarantine" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

