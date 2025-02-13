rule Backdoor_Win32_Zeprox_B_2147670696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zeprox.B"
        threat_id = "2147670696"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeprox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 00 8b f0 85 f6 7e 38 c7 45 ?? 01 00 00 00 8b 45 ?? 8b 55 ?? 0f b6 44 10 ff 83 e8 20 8b df 33 d8 83 c3 20 8d 45 ?? 8b d3 e8 ?? ?? ff ff 8b 55 ?? 8d 45 ?? e8 ?? ?? ff ff 47 ff 45 ?? 4e 75 cf}  //weight: 2, accuracy: Low
        $x_1_2 = "Svc2dll" ascii //weight: 1
        $x_1_3 = "#jnd" ascii //weight: 1
        $x_1_4 = "\\Application Data\\Macromedia\\Flash Player\\#SharedObjects" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

