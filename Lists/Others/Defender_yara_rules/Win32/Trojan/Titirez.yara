rule Trojan_Win32_Titirez_RPI_2147832529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Titirez.RPI!MTB"
        threat_id = "2147832529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Titirez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 05 04 70 56 00 8b 0d bc 82 56 00 03 8d cc fe ff ff 0f b6 11 33 d0 a1 bc 82 56 00 03 85 cc fe ff ff 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

