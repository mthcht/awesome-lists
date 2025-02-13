rule Trojan_Win32_Arcyess_A_2147696634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arcyess.A!dha"
        threat_id = "2147696634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arcyess"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s\\%d.bat" wide //weight: 2
        $x_2_2 = "The current thread is probably stale!" wide //weight: 2
        $x_2_3 = "Locking doors" wide //weight: 2
        $x_2_4 = "I'm going to start it" wide //weight: 2
        $x_2_5 = "/dispatch.asp" wide //weight: 2
        $x_2_6 = "Engine started" wide //weight: 2
        $x_2_7 = "Running in background" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

