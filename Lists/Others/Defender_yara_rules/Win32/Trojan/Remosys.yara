rule Trojan_Win32_Remosys_C_2147731206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Remosys.C"
        threat_id = "2147731206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Remosys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\lexjusto\\Desktop\\exit\\Release\\exit.pdb" ascii //weight: 1
        $x_1_2 = "cmd.exe /C i.cmd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

