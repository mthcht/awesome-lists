rule Trojan_Win32_Falabud_G_2147756687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Falabud.G"
        threat_id = "2147756687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Falabud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cmd /c" wide //weight: 10
        $x_10_2 = "findstr" wide //weight: 10
        $x_10_3 = "wmic" wide //weight: 10
        $x_10_4 = "hotfixid" wide //weight: 10
        $x_10_5 = "kb4499175" wide //weight: 10
        $x_10_6 = "rdtoggle" wide //weight: 10
        $x_10_7 = "SetAllowTSConnections" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Falabud_H_2147756688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Falabud.H"
        threat_id = "2147756688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Falabud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "90"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mshta" wide //weight: 10
        $x_10_2 = "vbscript" wide //weight: 10
        $x_10_3 = "wscript" wide //weight: 10
        $x_10_4 = "shell" wide //weight: 10
        $x_10_5 = "run" wide //weight: 10
        $x_10_6 = "for" wide //weight: 10
        $x_10_7 = "msiexec" wide //weight: 10
        $x_10_8 = "http://" wide //weight: 10
        $x_10_9 = "window.close" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

