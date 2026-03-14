rule Trojan_Win32_BurrowShell_AMTB_2147964747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BurrowShell!AMTB"
        threat_id = "2147964747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BurrowShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "C:\\Users\\pakis\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\" ascii //weight: 5
        $x_2_2 = "start keylogstop keylogscreenshotdownload Error uploading file:" ascii //weight: 2
        $x_2_3 = "Sleep irregularity: slept for s instead of calculated s (base: s, jitter: %)" ascii //weight: 2
        $x_2_4 = "COMPUTERNAMEUSERNAMEhostnamewhoamiRegistration failed after  attempts:" ascii //weight: 2
        $x_2_5 = "Keylogger startedKeylogger is already runningCommand execution took " ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

