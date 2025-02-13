rule Trojan_Win32_Elzob_DSK_2147755705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Elzob.DSK!MTB"
        threat_id = "2147755705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Elzob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 10 0f b6 96 30 21 40 00 03 c3 0f b6 08 33 ff 33 cf 47 81 ff ff 00 00 00 7c ?? 32 ca 88 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

