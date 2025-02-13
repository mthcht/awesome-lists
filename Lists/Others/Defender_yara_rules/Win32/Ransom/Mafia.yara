rule Ransom_Win32_Mafia_A_2147728634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mafia.A"
        threat_id = "2147728634"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swchost.exe" ascii //weight: 1
        $x_1_2 = "onion." ascii //weight: 1
        $x_1_3 = "/mafiaEgnima.php" ascii //weight: 1
        $x_1_4 = ".MAFIA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

