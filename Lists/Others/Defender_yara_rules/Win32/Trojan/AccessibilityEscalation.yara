rule Trojan_Win32_AccessibilityEscalation_GR_2147755306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccessibilityEscalation.GR!MSR"
        threat_id = "2147755306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccessibilityEscalation"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/v ShowSuperHidden /t REG_DWORD /d 0 /f" ascii //weight: 1
        $x_2_2 = "Image File Execution Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"C:\\windows\\system32\\taskmgr.exe\" /f" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_AccessibilityEscalation_C_2147931988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccessibilityEscalation.C"
        threat_id = "2147931988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccessibilityEscalation"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "utilman.exe" wide //weight: 1
        $x_1_2 = "sethc.exe" wide //weight: 1
        $x_1_3 = "osk.exe" wide //weight: 1
        $x_1_4 = "magnify.exe" wide //weight: 1
        $x_1_5 = "narrator.exe" wide //weight: 1
        $x_1_6 = "displayswitch.exe" wide //weight: 1
        $x_1_7 = "atbroker.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_AccessibilityEscalation_BT_2147951924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AccessibilityEscalation.BT"
        threat_id = "2147951924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AccessibilityEscalation"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "atbroker.exe" wide //weight: 1
        $x_1_2 = "osk.exe" wide //weight: 1
        $x_1_3 = "utilman.exe" wide //weight: 1
        $x_1_4 = "DisplaySwitch.exe" wide //weight: 1
        $x_1_5 = "narrator.exe" wide //weight: 1
        $x_1_6 = "magnify.exe" wide //weight: 1
        $x_1_7 = "/start narrator " wide //weight: 1
        $x_1_8 = "/start magnifierpane " wide //weight: 1
        $x_1_9 = "sethc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

