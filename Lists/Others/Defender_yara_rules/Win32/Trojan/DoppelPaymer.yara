rule Trojan_Win32_DoppelPaymer_2147761924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DoppelPaymer!MTB"
        threat_id = "2147761924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DoppelPaymer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 8d 4e 34 e8 ?? ?? ff ff 8b 08 e8 ?? ?? ff ff 35 ?? ?? ?? ?? 8d 4d dc 89 46 3c e8 ?? ?? ff ff 8b 57 48 8b 45 f4 89 56 20 89 46 40 8b 4f 50 6a ff 89 4e 28 8b 4d fc 56 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

