rule Trojan_Win32_TampEnum_A_2147942421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TampEnum.A!MTB"
        threat_id = "2147942421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TampEnum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tasklist" wide //weight: 1
        $x_1_2 = "imagename eq MsMpEng.exe" wide //weight: 1
        $x_1_3 = "find" wide //weight: 1
        $x_1_4 = "PID" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

