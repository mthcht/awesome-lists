rule Trojan_Win32_SuspWmiUsage_ZPA_2147934416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiUsage.ZPA"
        threat_id = "2147934416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiUsage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "useraccount get /ALL /format:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWmiUsage_ZPB_2147934417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiUsage.ZPB"
        threat_id = "2147934417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiUsage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "process get caption" wide //weight: 1
        $x_1_3 = "executablepath" wide //weight: 1
        $x_1_4 = "commandline" wide //weight: 1
        $x_1_5 = "/format:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWmiUsage_ZPC_2147934418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiUsage.ZPC"
        threat_id = "2147934418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiUsage"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic" wide //weight: 1
        $x_1_2 = "qfe get description" wide //weight: 1
        $x_1_3 = "installedOn" wide //weight: 1
        $x_1_4 = "/format:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

