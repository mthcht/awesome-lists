rule Trojan_Win32_DllSideLoading_PC_2147971844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllSideLoading.PC!MTB"
        threat_id = "2147971844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllSideLoading"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 90 b8 cd cc cc cc f7 e6 8b c6 c1 ea 03 8d 0c 92 03 c9 2b c1 8b 4d 10 8a 44 05 e8 30 04 0e 46 3b f7 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

