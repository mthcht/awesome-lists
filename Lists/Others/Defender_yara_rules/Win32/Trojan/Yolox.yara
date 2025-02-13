rule Trojan_Win32_Yolox_A_2147907233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yolox.A!MTB"
        threat_id = "2147907233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yolox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 03 c0 40 32 cb 0f b6 d0 33 c0 40 f6 d1 80 d9 ?? 0f c0 c2 0f ba fa}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

