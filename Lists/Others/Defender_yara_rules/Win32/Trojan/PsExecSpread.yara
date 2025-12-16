rule Trojan_Win32_PsExecSpread_B_2147959524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsExecSpread.B!MTB"
        threat_id = "2147959524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsExecSpread"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 5c 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 20 00 2d 00 63 00 20 00 [0-80] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "--spread" wide //weight: 1
        $x_1_3 = "--password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

