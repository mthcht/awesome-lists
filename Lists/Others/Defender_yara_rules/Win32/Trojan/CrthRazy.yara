rule Trojan_Win32_CrthRazy_A_2147741651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CrthRazy.A"
        threat_id = "2147741651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CrthRazy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Safe Browsing Extension Blacklist" ascii //weight: 1
        $x_1_2 = "Software\\Policies\\YandexBrowser" ascii //weight: 1
        $x_1_3 = "/ModularInstaller.exe" ascii //weight: 1
        $x_1_4 = "/S /C choice /C Y /N /D Y /T 3" ascii //weight: 1
        $x_1_5 = "{FA1B727D-3970-456" ascii //weight: 1
        $x_1_6 = "1-8AC6-AC8AA7DBA639}" ascii //weight: 1
        $x_1_7 = "HARDWARE\\DESCRIPTION\\System\\Bios" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

