rule Trojan_Win32_CredStealzClick_ZA_2147971495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredStealzClick.ZA!MTB"
        threat_id = "2147971495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredStealzClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "findstr  /si credential" wide //weight: 10
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

rule Trojan_Win32_CredStealzClick_Z_2147971741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredStealzClick.Z!MTB"
        threat_id = "2147971741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredStealzClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "findstr  /si credential" wide //weight: 10
        $x_1_2 = "*.txt" wide //weight: 1
        $x_1_3 = "*.config" wide //weight: 1
        $x_1_4 = "*.cfg" wide //weight: 1
        $x_1_5 = "*.conf" wide //weight: 1
        $x_1_6 = "*.ini" wide //weight: 1
        $x_1_7 = "*.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

