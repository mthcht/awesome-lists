rule Trojan_Win32_Vbmalin_A_2147628902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vbmalin.A"
        threat_id = "2147628902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vbmalin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Pocong.exe" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" wide //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\W32.Formalin" wide //weight: 1
        $x_1_4 = "Your computer has been infected virus" wide //weight: 1
        $x_1_5 = "Games.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

