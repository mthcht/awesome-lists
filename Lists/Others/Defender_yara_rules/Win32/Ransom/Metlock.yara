rule Ransom_Win32_Metlock_A_2147694618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Metlock.A"
        threat_id = "2147694618"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Metlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_DarkMetro" ascii //weight: 1
        $x_1_2 = "AntiWinLockerTray.exe" ascii //weight: 1
        $x_1_3 = "ServiceAntiWinLocker.exe" ascii //weight: 1
        $x_1_4 = {c7 e0 e1 eb ee ea e8 f0 ee e2 e0 ed 21 21 21 20 d3 e1 e8 e9 f1 f2 e2 ee 20 ef f0 ee f6 e5 f1 f1 ee f0 e0 20 c2 ca cb 20 2b 00}  //weight: 1, accuracy: High
        $x_1_5 = {f0 ee eb fc 2c 20 ea ee f2 ee f0 fb e9 20 e7 ed e0 fe 20 f2 ee eb fc ea ee 20 ff 2e 0d 0a c8 ed e0 f7 e5 20 ea ee ec ef f3 20 ef e8 e7 e4 e0 21 0d 0a c5 f1 f2 fc 20 32 20 e2 e0}  //weight: 1, accuracy: High
        $x_1_6 = {cd e5 e2 e5 f0 ed fb e9 20 ef e0 f0 ee eb fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

