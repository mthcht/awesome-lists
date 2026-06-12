rule Trojan_Win32_PassStealzClick_ZA_2147971494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PassStealzClick.ZA!MTB"
        threat_id = "2147971494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PassStealzClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "findstr /si password" wide //weight: 10
        $x_1_2 = "*.txt" wide //weight: 1
        $x_1_3 = "*.config" wide //weight: 1
        $x_1_4 = "*.cfg" wide //weight: 1
        $x_1_5 = "*.conf" wide //weight: 1
        $x_1_6 = "*.ini" wide //weight: 1
        $x_1_7 = "*.vbs" wide //weight: 1
        $n_10_8 = "ddbf9b05-fcb0-4fce-949e-a6ae899ab273" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

