rule Trojan_Win32_ConnectWise_2147982569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ConnectWise!atmn"
        threat_id = "2147982569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ConnectWise"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "34"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "schtasks" wide //weight: 5
        $x_7_2 = "/tn MicrosoftEdgeUpdate" wide //weight: 7
        $x_10_3 = "\\AppData\\Local\\MicrosoftEdgeUpdate\\MicrosoftEdgeUpdate.exe" wide //weight: 10
        $x_7_4 = "/sc ONLOGON" wide //weight: 7
        $x_5_5 = "/rl LIMITED" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

