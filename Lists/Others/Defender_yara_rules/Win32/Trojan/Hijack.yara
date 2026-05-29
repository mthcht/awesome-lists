rule Trojan_Win32_Hijack_ARR_2147965719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hijack.ARR!MTB"
        threat_id = "2147965719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {8a 16 8b f9 8b e9 32 10 40 88 16 83 ef}  //weight: 15, accuracy: High
        $x_5_2 = "POSGrabber_mutated.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Hijack_ARR_2147965719_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hijack.ARR!MTB"
        threat_id = "2147965719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = {0f 11 49 d0 3b c2 72 ?? 3b c7 73 09 80 34 06 ?? 40 3b c7 72}  //weight: 12, accuracy: Low
        $x_8_2 = {0f 28 ca 0f 57 c2 0f 11 41 a0 0f 10 41 b0 0f 57 c8 0f 11 49 b0 0f 28 ca 0f 10 41 c0 0f 57 c8 0f 11 49 c0 0f 28 ca}  //weight: 8, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

