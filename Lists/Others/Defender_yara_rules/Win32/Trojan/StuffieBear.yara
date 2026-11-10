rule Trojan_Win32_StuffieBear_ZZ_2147981805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StuffieBear.ZZ!sms"
        threat_id = "2147981805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StuffieBear"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 fd 8a 55 fe 88 45 fc 88 45 ff 8d 45 fc 88 4d fe 50 8b c8 88 55 fd e8 ?? ?? ?? ?? 8b 45 f8 99 f7 fb c1 e0 02}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 7d 08 6a 04 8d 5f 1c 5e 8b 07 8b ce d3 c8 30 04 3e 46 83 fe 1c 72 ?? 6a 04 5e 8b 03 8b ce d3 c8 30 04 1e 46 83 fe 18 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

