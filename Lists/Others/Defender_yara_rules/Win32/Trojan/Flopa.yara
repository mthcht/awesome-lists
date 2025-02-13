rule Trojan_Win32_Flopa_FSG_2147816719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flopa.FSG!MSR"
        threat_id = "2147816719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flopa"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WELCOME TO FLOPA TROJAN" ascii //weight: 2
        $x_1_2 = "HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command" wide //weight: 1
        $x_1_3 = "explorer.exe, C:\\Program Files\\Temp\\hell.exe" ascii //weight: 1
        $x_1_4 = "DisableRegistryTools" wide //weight: 1
        $x_1_5 = "POTATOES.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

