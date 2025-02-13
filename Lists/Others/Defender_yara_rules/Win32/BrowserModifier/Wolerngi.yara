rule BrowserModifier_Win32_Wolerngi_228033_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Wolerngi"
        threat_id = "228033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolerngi"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GS_CheckUpdate" ascii //weight: 1
        $x_1_2 = "GS_RuleList" ascii //weight: 1
        $x_1_3 = "[N] ProductKey :" ascii //weight: 1
        $x_1_4 = "gencolabsllc.com/services/update.php?affid=" ascii //weight: 1
        $x_1_5 = "cmd.exe /c net start GSafe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Wolerngi_228033_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Wolerngi"
        threat_id = "228033"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Wolerngi"
        severity = "33"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "62"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "P_RuleList" ascii //weight: 20
        $x_20_2 = "P_CheckUpdate" ascii //weight: 20
        $x_20_3 = "[N] ProductKey :" ascii //weight: 20
        $x_1_4 = "related.deals/services/rules" ascii //weight: 1
        $x_1_5 = "related.deals/services/update" ascii //weight: 1
        $x_1_6 = "softwarellc.com/services/rules.txt?" ascii //weight: 1
        $x_1_7 = "softwarellc.com/services/update.php?" ascii //weight: 1
        $x_1_8 = "desprotetordelinks.me/services/rules.txt?" ascii //weight: 1
        $x_1_9 = "desprotetordelinks.me/services/update.php?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

