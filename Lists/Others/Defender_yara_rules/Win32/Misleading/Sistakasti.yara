rule Misleading_Win32_Sistakasti_240758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Sistakasti"
        threat_id = "240758"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Sistakasti"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Pointstone\\System Cleaner" ascii //weight: 1
        $x_1_2 = "\\Integrator.exe\" --scan-automatically" ascii //weight: 1
        $x_1_3 = {43 72 65 61 74 65 73 20 61 20 73 68 6f 72 74 63 75 74 20 74 6f 20 53 79 73 74 65 6d 20 43 6c 65 61 6e 65 72 20 [0-3] 20 6f 6e 20 79 6f 75 72 20 51 75 69 63 6b 20 4c 61 75 6e 63 68 20 66 6f 6c 64 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 53 79 73 74 65 6d 20 43 6c 65 61 6e 65 72 20 [0-3] 5c 55 74 69 6c 69 74 69 65 73 5c 50 6f 69 6e 74 73 74 6f 6e 65 20 44 69 73 6b 20 44 65 66 72 61 67 2e 6c 6e 6b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Misleading_Win32_Sistakasti_240758_1
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Sistakasti"
        threat_id = "240758"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Sistakasti"
        severity = "Mid"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Pointstone.SystemCleaner.Protector.Detector" ascii //weight: 2
        $x_2_2 = "System Cleaner is a registered trademark of Pointstone Software, LLC." wide //weight: 2
        $x_1_3 = "SysClean.WelcomeSimple.Strings" ascii //weight: 1
        $x_1_4 = "Recommendations.Frame.FixProgress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

