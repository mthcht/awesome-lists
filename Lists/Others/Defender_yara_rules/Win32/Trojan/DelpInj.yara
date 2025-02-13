rule Trojan_Win32_DelpInj_2147747930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelpInj!MTB"
        threat_id = "2147747930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelpInj"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 0f b6 44 38 ff 33 45 f8 89 45 f4 8d 45 f0 8a 55 f4 e8 ?? ?? ?? ?? 8b 55 f0 8b c6 e8 ?? ?? ?? ?? 47 4b 75 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

