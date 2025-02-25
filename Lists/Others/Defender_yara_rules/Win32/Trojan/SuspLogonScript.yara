rule Trojan_Win32_SuspLogonScript_ZPA_2147934413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLogonScript.ZPA"
        threat_id = "2147934413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLogonScript"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " add " wide //weight: 1
        $x_1_2 = "/v UserInitMprLogonScript" wide //weight: 1
        $x_1_3 = "/t REG_SZ" wide //weight: 1
        $x_1_4 = " /d" wide //weight: 1
        $x_1_5 = "\\Environment" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

