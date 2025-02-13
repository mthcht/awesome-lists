rule Trojan_Win32_InjectInstecb_S_2147730913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/InjectInstecb.S"
        threat_id = "2147730913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectInstecb"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VBoxCredProv.dll" wide //weight: 1
        $x_1_2 = "\\WIRE1x 2.5\\Uninstall.lnk" wide //weight: 1
        $x_1_3 = "RMDir: RemoveDirectory on Reboot(\"%s\")" wide //weight: 1
        $x_1_4 = "\\HydraIRC.exe" wide //weight: 1
        $x_1_5 = "Software\\Ghisler\\Total Commander" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

