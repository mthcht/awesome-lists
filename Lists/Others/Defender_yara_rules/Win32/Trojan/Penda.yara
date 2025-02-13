rule Trojan_Win32_Penda_18097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Penda"
        threat_id = "18097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Penda"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 4b fc ff ff 83 c4 24 33 c0 bb ?? ?? 00 00 80 b0 ?? ?? 40 00 ?? 40 3b c3 72 f4 8b 3d ?? ?? 40 00 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

