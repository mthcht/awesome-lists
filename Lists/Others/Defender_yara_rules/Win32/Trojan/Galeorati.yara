rule Trojan_Win32_Galeorati_A_2147652106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Galeorati.A"
        threat_id = "2147652106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Galeorati"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lheora & Avaga (" wide //weight: 1
        $x_1_2 = "CurrentVersion\\Run\\Java UI" wide //weight: 1
        $x_1_3 = "\\LCGUI.exe" wide //weight: 1
        $x_1_4 = "Startup\\Lheora.exe" wide //weight: 1
        $x_1_5 = "WScript.Shell" wide //weight: 1
        $x_1_6 = "Aku Cinta Kamu Lheora" wide //weight: 1
        $x_1_7 = "Larassati" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

