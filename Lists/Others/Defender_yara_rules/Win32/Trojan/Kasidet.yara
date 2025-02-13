rule Trojan_Win32_Kasidet_GJW_2147835061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kasidet.GJW!MTB"
        threat_id = "2147835061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kasidet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 c6 44 24 ?? 66 c6 44 24 ?? 65 c6 44 24 ?? 78 c6 44 24 ?? 69 c6 44 24 ?? 73 c6 44 24 ?? 74 c6 44 24 ?? 70 c6 44 24 ?? 31 c6 44 24 ?? 67 c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 6f c6 44 24 6a 6e c6 44 24 ?? 66}  //weight: 10, accuracy: Low
        $x_1_2 = "%s\\flash_%s.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

