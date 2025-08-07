rule Trojan_Win32_TempoToad_A_2147948685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TempoToad.A"
        threat_id = "2147948685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TempoToad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 8b ?? ?? ?? ff ff ?? 6a 00 ff ?? ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 40 8b 85 ?? ?? ff ff ?? 8b ?? ?? ?? ff ff ?? ff ?? ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

