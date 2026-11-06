rule Trojan_Win32_LogonScriptTask_A_2147981695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LogonScriptTask.A"
        threat_id = "2147981695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LogonScriptTask"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = "/sc onlogon" wide //weight: 1
        $x_1_4 = "schedule.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

