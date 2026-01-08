rule Trojan_Win32_SDum_BMD_2147960764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SDum.BMD!MTB"
        threat_id = "2147960764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SDum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b c8 41 83 e1 ?? 47 0f b6 0c 01 44 30 0c 01 48 ff c0 48 3b c2 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

