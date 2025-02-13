rule Trojan_Win32_TurtleLoaderEnc_A_2147780148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TurtleLoaderEnc.A!dha"
        threat_id = "2147780148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TurtleLoaderEnc"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@[*] WriteProcessMemory:" ascii //weight: 1
        $x_1_2 = "@[*] Sleeping to evade in memory scanners" ascii //weight: 1
        $x_1_3 = "@ using password:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

