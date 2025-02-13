rule TrojanDropper_Win32_Wador_A_2147649397_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Wador.A"
        threat_id = "2147649397"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Wador"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 34 10 89 40 3b c1 72 f7}  //weight: 2, accuracy: High
        $x_1_2 = {01 6f 75 23 80 ?? ?? 02 6f 75 1c 80 ?? ?? 03 6b 75 15 80 ?? ?? 05 72 75 0e 80 ?? ?? 06 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "%s %s /isa release" ascii //weight: 1
        $x_1_4 = "\\\\.\\Bios" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

