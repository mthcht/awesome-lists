rule Trojan_Win32_Bxmin_A_2147895118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bxmin.A!MTB"
        threat_id = "2147895118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bxmin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0f 80 f1 ?? 46 88 08 39 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 0b 80 f1 ?? 46 88 08 39 75}  //weight: 2, accuracy: Low
        $x_2_3 = {8d 85 dc fe ff ff 50 ff 15 ?? 30 40 00 59 8b f0 8a 45 f3 53 8d 4d e0 88 45 e0 ff 15 ?? 30 40 00 56 e8 ?? 11 00 00 59 50 56 8d 4d e0 ff 15 ?? 30 40 00 8d 45 e0 68 ?? 40 40 00 50 89 5d fc ff 15 ?? 30 40 00 83 4d fc ff 59 59 88 45 f3 6a 01 8d 4d e0 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

