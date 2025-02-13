rule Trojan_Win32_OilRig_A_2147747935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/OilRig.A!MSR"
        threat_id = "2147747935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "OilRig"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "\\exeruner\\exeruner" ascii //weight: 5
        $x_5_2 = "rUpdateChecker.ps1" wide //weight: 5
        $x_1_3 = "/c powershell -exec bypass -window hidden -nologo -command" wide //weight: 1
        $x_1_4 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn \"\\UpdateTasks\\JavaUpdates\" /tr \"wscript /b \\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

