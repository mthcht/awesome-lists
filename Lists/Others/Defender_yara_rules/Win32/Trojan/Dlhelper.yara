rule Trojan_Win32_Dlhelper_SA_2147740897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dlhelper.SA"
        threat_id = "2147740897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dlhelper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/RestartByRestartManager:C4E8D0E1-988D-42b7-BEA7-6BF9589BB111" wide //weight: 1
        $x_1_2 = "\\yunxibengdi.bat" ascii //weight: 1
        $x_1_3 = "netsh advfirewall firewall add rule name=\"" ascii //weight: 1
        $x_1_4 = ":\\NetAccerAWS\\Release\\NetAccerAWS.pdb" ascii //weight: 1
        $x_1_5 = "\\clinkapp.data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

