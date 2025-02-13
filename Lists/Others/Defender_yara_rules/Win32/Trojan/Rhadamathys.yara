rule Trojan_Win32_Rhadamathys_PAA_2147841641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rhadamathys.PAA!MTB"
        threat_id = "2147841641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rhadamathys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 3c 24 89 54 24 ?? 89 da c1 e2 ?? 03 54 24 ?? 8d 3c 33 31 d7 89 da c1 ea ?? 01 ea 31 fa 29 d0 89 c2 c1 e2 ?? 03 14 24 8d 3c 06 31 d7 89 c2 c1 ea ?? 03 54 24 ?? 31 fa 29 d3 81 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

