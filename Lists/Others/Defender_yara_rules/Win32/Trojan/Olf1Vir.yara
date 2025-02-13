rule Trojan_Win32_Olf1Vir_A_2147735728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Olf1Vir.A"
        threat_id = "2147735728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Olf1Vir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Olf1VirAtC" wide //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\11.0\\Word\\Security\\AccessVBOM" wide //weight: 1
        $x_1_3 = "C:\\StopMSO1033.txt" wide //weight: 1
        $x_1_4 = "C:\\Windows\\Olf1VirMSO1033.doc" wide //weight: 1
        $x_1_5 = "C:\\Olf1VirDir\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

