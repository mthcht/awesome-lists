rule Trojan_Win32_RMSRat_A_2147897078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RMSRat.A!MTB"
        threat_id = "2147897078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RMSRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c3 0f b6 ca 0f af c8 8a 44 24 ?? 02 0c 2b 32 c1 43 88 44 24 ?? 88 04 32 83 fb}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 c9 0f b6 c3 0f af c8 8b 44 24 ?? 02 0c 28 32 d1 8b c8 41 88 14 33 89 4c 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

