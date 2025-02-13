rule Trojan_Win32_DarkShadowWiper_A_2147773770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkShadowWiper.A!dha"
        threat_id = "2147773770"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkShadowWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "1e2fe2b5-d728-40cd-978c-843dbe38893e" ascii //weight: 3
        $x_2_2 = "Wiper-action" ascii //weight: 2
        $x_2_3 = "/create /sc ONSTART /tn \"MicrosoftCrashHandlerUAC" ascii //weight: 2
        $x_2_4 = "Global-XSjzmQixFXFfHO3npSYS" wide //weight: 2
        $x_1_5 = "remover.bat" wide //weight: 1
        $x_1_6 = "rundll32.exe advapi32.dll,ProcessIdleTasks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DarkShadowWiper_C_2147775453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkShadowWiper.C!dha"
        threat_id = "2147775453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkShadowWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = "CrashHandlerUAC" wide //weight: 1
        $n_10_4 = "/disable" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

