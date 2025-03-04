rule Trojan_Win32_Mydoom_GPA_2147901695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mydoom.GPA!MTB"
        threat_id = "2147901695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mydoom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 8f 68 91 50 00 80 f1 ?? 88 8c 05 fc fd ff ff 40 3d 00 02 00 00 89 45 fc 7c 18 8d 4d fc 6a 00 51 50 8d 85 fc fd ff ff 50 ff 75 08 ff d6 33 c0 89 45 fc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

