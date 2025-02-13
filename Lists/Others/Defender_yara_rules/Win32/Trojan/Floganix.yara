rule Trojan_Win32_Floganix_A_2147624524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Floganix.A"
        threat_id = "2147624524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Floganix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 4d f8 4b 47 80 3b 72 75 3a 56 89 5d fc ff 15 ?? ?? ?? ?? 83 65 f4 00 85 c0 89 45 f0 76 1f 8b cb 0f be 04 0f 0f b6 11 3b c2 75 0e}  //weight: 3, accuracy: Low
        $x_1_2 = "CFoxglinaModule" ascii //weight: 1
        $x_1_3 = {66 6f 78 67 6c 69 6e 61 2e 64 6c 6c 00 4e 53 47 65 74 4d 6f 64 75 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = "firehfxtiez" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

