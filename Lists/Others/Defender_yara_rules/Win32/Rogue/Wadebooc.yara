rule Rogue_Win32_Wadebooc_210234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Wadebooc"
        threat_id = "210234"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Wadebooc"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "AdwareBooC.Properties.Resources" wide //weight: 5
        $x_5_2 = "succes/index.php" wide //weight: 5
        $x_5_3 = "scripts/paydefault.php" wide //weight: 5
        $x_1_4 = "this information is anomized, we cannot see who sent it," wide //weight: 1
        $x_1_5 = "Pinball Browser Helper" wide //weight: 1
        $x_1_6 = "Program files\\spywarestrike\\lang" wide //weight: 1
        $x_1_7 = "UserName\\application data\\shudder" wide //weight: 1
        $x_1_8 = "Software\\AdwCleaner" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

