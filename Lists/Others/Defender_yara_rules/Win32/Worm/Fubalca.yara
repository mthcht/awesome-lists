rule Worm_Win32_Fubalca_A_2147601359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Fubalca.A"
        threat_id = "2147601359"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Fubalca"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 55 f8 80 c2 41 e8 ?? ?? ff ff 8b 95 ?? ?? ff ff 8d 45 f0 b9 ?? ?? ?? ?? e8 ?? ?? ff ff 8d 45 f4 50 68 3f 00 0f 00 6a 00 68 ?? ?? ?? ?? 68 01 00 00 80 e8 ?? ?? ff ff 33 c0 89 45 ec 6a 04 8d 45 ec 50 6a 04 6a 00 68 ?? ?? ?? ?? 8b 45 f4 50}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 45 ec ba 05 00 00 00 e8 ?? ?? ff ff 6a 00 68 ?? ?? ?? ?? e8 ?? ?? ff ff 68 ?? ?? 00 00 e8 ?? ?? ff ff 6a 00 8d 85 ?? ?? ff ff 8b 4d ec ba ?? ?? ?? ?? e8 ?? ?? ff ff 8b 85 ?? ?? ff ff e8 ?? ?? ff ff 50 e8 ?? ?? ff ff 6a 00}  //weight: 10, accuracy: Low
        $x_1_3 = "AutoRun.inf" ascii //weight: 1
        $x_1_4 = "[AutoRun]" ascii //weight: 1
        $x_1_5 = "shellexecute=" ascii //weight: 1
        $x_1_6 = "shell\\Auto\\command=" ascii //weight: 1
        $x_1_7 = "NoDriveTypeAutoRun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

