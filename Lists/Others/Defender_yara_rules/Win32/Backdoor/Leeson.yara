rule Backdoor_Win32_Leeson_B_2147811730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Leeson.B!dha"
        threat_id = "2147811730"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Leeson"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ef 33 c0 8b c8 81 e1 07 00 00 80}  //weight: 2, accuracy: High
        $x_1_2 = "__VIEWSTATE" ascii //weight: 1
        $x_1_3 = "__EVENTVALIDATION" ascii //weight: 1
        $x_1_4 = "&imageCon=" ascii //weight: 1
        $x_1_5 = "&messageCon=" ascii //weight: 1
        $x_1_6 = "&messageId=" ascii //weight: 1
        $x_1_7 = "%s\\adult.sft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Leeson_C_2147811732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Leeson.C!dha"
        threat_id = "2147811732"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Leeson"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adult.sft" wide //weight: 1
        $x_1_2 = "DownFile Success" ascii //weight: 1
        $x_1_3 = "DownFile Failure" ascii //weight: 1
        $x_1_4 = "RemoteExec Success" ascii //weight: 1
        $x_1_5 = "&stringsComand=" ascii //weight: 1
        $x_1_6 = "&stringsId=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Leeson_E_2147811734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Leeson.E!dha"
        threat_id = "2147811734"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Leeson"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\DF%05d.tmp" wide //weight: 1
        $x_1_2 = "\\Microsoft\\Media Player" wide //weight: 1
        $x_1_3 = "ClearBrowsingHistoryOnExit" wide //weight: 1
        $x_1_4 = "DisableFirstRunCustomize" wide //weight: 1
        $x_1_5 = "%s\\adult.sft" wide //weight: 1
        $x_1_6 = "%s\\Notice" wide //weight: 1
        $x_1_7 = "TEXTAREA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

