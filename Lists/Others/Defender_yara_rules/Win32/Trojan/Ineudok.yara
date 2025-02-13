rule Trojan_Win32_Ineudok_A_2147641386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ineudok.A"
        threat_id = "2147641386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ineudok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/win/eueu.php?upd=ok&vl=" wide //weight: 1
        $x_1_2 = "/vrnx/index.php?inf=shwh&cd=wmv&sd=" wide //weight: 1
        $x_1_3 = "GuardUSB" wide //weight: 1
        $x_1_4 = "thd32.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

