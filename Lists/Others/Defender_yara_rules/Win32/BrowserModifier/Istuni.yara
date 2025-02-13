rule BrowserModifier_Win32_Istuni_265835_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Istuni"
        threat_id = "265835"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Istuni"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OVERRIDE_FORCE_ENTERPRISE_INSTALL is 1 in settings.h, setting forceEnterpriseInstall to true" ascii //weight: 2
        $x_1_2 = "Firefox window captured. Handle is 0X" ascii //weight: 1
        $x_2_3 = ":\\GIT\\addonInstaller\\instui\\Release\\instui.pdb" ascii //weight: 2
        $x_2_4 = "Firefox window with style 0x96000000 captured (Add extension dialog window)" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

