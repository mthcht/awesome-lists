rule Trojan_Win32_Fakesvc_SA_2147777798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fakesvc.SA!MTB"
        threat_id = "2147777798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fakesvc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SVCHOSI.EXE" wide //weight: 1
        $x_1_2 = "K:\\EXE COMPILE" wide //weight: 1
        $x_1_3 = "K:\\A MASTER T\\WIN_KEEPER\\SVCHOSI.vbp" wide //weight: 1
        $x_1_4 = "\\ghost.bat" wide //weight: 1
        $x_1_5 = "\\Win-Secure\\wslogon.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

