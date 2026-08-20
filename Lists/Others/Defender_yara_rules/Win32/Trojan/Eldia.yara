rule Trojan_Win32_Eldia_2147976551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eldia!atmn"
        threat_id = "2147976551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eldia"
        severity = "Critical"
        info = "atmn: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "EldiaCordLauncher.exe" wide //weight: 5
        $x_5_2 = "EldiaMemory.exe" wide //weight: 5
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "Starting download stream..." wide //weight: 1
        $x_1_5 = "[SYS_INIT] ESTABLISHING SECURE PROTOCOL..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

