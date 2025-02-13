rule Trojan_Win32_Lofumin_A_2147711515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lofumin.A"
        threat_id = "2147711515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lofumin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ModuleGS\\Mainer\\SystemNT.exe" wide //weight: 1
        $x_1_2 = "golf-stream.ucoz.net/Module/MinerGet/MinerGate" wide //weight: 1
        $x_1_3 = "USB_INFECT" wide //weight: 1
        $x_1_4 = "Start maining." wide //weight: 1
        $x_1_5 = "[zapros_logstart_otvet]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

