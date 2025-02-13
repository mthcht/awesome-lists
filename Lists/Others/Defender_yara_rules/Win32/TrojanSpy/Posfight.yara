rule TrojanSpy_Win32_Posfight_A_2147694092_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Posfight.A"
        threat_id = "2147694092"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Posfight"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bot/command.php?id=" wide //weight: 1
        $x_1_2 = "bot/log.php?id=" wide //weight: 1
        $x_1_3 = "] Failed to download File: " wide //weight: 1
        $x_1_4 = "] HTTP-Flood started at:" wide //weight: 1
        $x_1_5 = "\\[KEYLOG]" wide //weight: 1
        $x_1_6 = "] New Infection" wide //weight: 1
        $x_1_7 = "] Novo Infection" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

