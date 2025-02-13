rule Trojan_Win32_FakeMadoc_141844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeMadoc"
        threat_id = "141844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeMadoc"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 00 2e 00 2a 00 00 00 2e 00 65 00 78 00 65 00 00 00 00 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = {6a 64 ff 15 ?? ?? ?? ?? eb 2f 66 83 7c 24 ?? 2e 75 18 66 83 7c 24 ?? 00 74 1f 66 83 7c 24 ?? 2e 75 08 66 83 7c 24 ?? 00 74 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 6a 64 68 37 12 00 00 ff 73 08 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

