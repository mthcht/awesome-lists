rule Trojan_Win32_Buhtrap_ARR_2147965243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Buhtrap.ARR!MTB"
        threat_id = "2147965243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Buhtrap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {d3 ea 32 54 04 ?? 0f be c0 6b c0 ?? 32 d0 88 54 24 ?? 3b f7 73}  //weight: 15, accuracy: Low
        $x_3_2 = "[-] Malformed field: %lx" ascii //weight: 3
        $x_2_3 = "Invalid payload:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

