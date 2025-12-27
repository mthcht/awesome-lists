rule Tampering_Win32_EDRFreeze_A_2147953447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Tampering:Win32/EDRFreeze.A"
        threat_id = "2147953447"
        type = "Tampering"
        platform = "Win32: Windows 32-bit platform"
        family = "EDRFreeze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to create PPL process." ascii //weight: 1
        $x_1_2 = "PROTECTION_LEVEL_WINTCB_LIGHT" ascii //weight: 1
        $x_1_3 = "Kill WER successfully. PID:" ascii //weight: 1
        $x_1_4 = "/encfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

