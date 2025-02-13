rule TrojanSpy_Win32_Adept_A_2147621457_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Adept.A"
        threat_id = "2147621457"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Adept"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 fb 0a 74 15 80 fb 0d 74 10 8b c6 99 f7 7d ?? 8b 45 ?? 8a 04 02 32 c3 88 01}  //weight: 2, accuracy: Low
        $x_1_2 = {74 37 66 81 7d 10 bb 01 74 07 68 ?? ?? ?? ?? eb 05}  //weight: 1, accuracy: Low
        $x_1_3 = "_O_K_" ascii //weight: 1
        $x_1_4 = "Start Audit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

