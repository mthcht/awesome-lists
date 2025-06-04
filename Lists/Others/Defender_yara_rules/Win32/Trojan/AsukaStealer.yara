rule Trojan_Win32_AsukaStealer_GVA_2147942782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AsukaStealer.GVA!MTB"
        threat_id = "2147942782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AsukaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 75 30 8a 14 0a 8d 8d 48 ff ff ff 32 14 3e e8 f6 81 00 00 47 3b 7d 18 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

