rule Trojan_Win32_Miser_C_2147697453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Miser.C"
        threat_id = "2147697453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Miser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5c 8d 8d 60 ff ff ff 51 ff 15 ?? ?? 40 00 6a 72 8d 95 50 ff ff ff 52 ff 15 ?? ?? 40 00 6a 73 8d 85 30 ff ff ff 50 ff 15 ?? ?? 40 00 6a 72 8d 8d 10 ff ff ff 51 ff 15 ?? ?? 40 00 6a 6b 8d 95 f0 fe ff ff 52 ff 15 ?? ?? 40 00 6a 5c 8d 85 d0 fe ff ff 50 ff 15 ?? ?? 40 00 6a 32 8d 8d b0 fe ff ff 51 ff 15 ?? ?? 40 00 6a 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

