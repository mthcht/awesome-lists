rule Trojan_Win32_PonyLoader_DEA_2147756327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PonyLoader.DEA!MTB"
        threat_id = "2147756327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PonyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 f0 8b 55 08 03 32 8b 45 08 89 30 8b 4d 08 8b 11 81 ea 36 a6 06 00 8b 45 08 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

