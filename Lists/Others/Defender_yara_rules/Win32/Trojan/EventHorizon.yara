rule Trojan_Win32_EventHorizon_A_2147832223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EventHorizon.A!dha"
        threat_id = "2147832223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EventHorizon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 b8 2d 65 6d 62 c7 45 bc 65 64 64 69 c7 45 c0 6e 67 4f 62 c7 45 c4 6a 65 63 74}  //weight: 1, accuracy: High
        $x_1_2 = {4c 8b 40 08 48 8d 15 ?? fa 0c 00 48 8d 4d d8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

