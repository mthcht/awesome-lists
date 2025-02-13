rule Trojan_Win32_Apost_G_2147751808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Apost.G!MTB"
        threat_id = "2147751808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Apost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 38 eb [0-37] 80 f3 [0-37] [0-10] 80 f3 [0-21] [0-10] 88 1c 38}  //weight: 1, accuracy: Low
        $x_1_2 = {a7 8a 1c 38 [0-16] 80 f3 [0-21] f6 d3 [0-16] 80 f3 [0-37] 88 1c 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

