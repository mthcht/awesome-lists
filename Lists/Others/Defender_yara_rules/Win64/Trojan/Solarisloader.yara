rule Trojan_Win64_Solarisloader_BA_2147982464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Solarisloader.BA!MTB"
        threat_id = "2147982464"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Solarisloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 43 8d 0c 30 c1 e0 0d 41 ff c0 33 f8 8b c7 c1 e8 11 33 f8 8b c7 c1 e0 05 33 f8 48 8b 45 ?? 40 8a d7 80 f2 ?? 88 14 01 45 3b c5 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

