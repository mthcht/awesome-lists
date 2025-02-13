rule TrojanSpy_Win32_Cospet_A_2147640377_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Cospet.A"
        threat_id = "2147640377"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Cospet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Set MyShell = CreateObject(\"Wscript.Shell\")" ascii //weight: 1
        $x_1_2 = "\\Autorun.vbs" ascii //weight: 1
        $x_1_3 = "http://checkip.dyndns.org" ascii //weight: 1
        $x_1_4 = "\"#Steam_Login_RememberPassword\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

