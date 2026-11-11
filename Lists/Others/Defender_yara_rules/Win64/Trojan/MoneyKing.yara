rule Trojan_Win64_MoneyKing_A_2147981887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/MoneyKing.A!dha"
        threat_id = "2147981887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "MoneyKing"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Enter search term (description, amount, or category):" ascii //weight: 1
        $x_1_2 = "Enter transaction type (Income/Expense):" ascii //weight: 1
        $x_1_3 = "Description | Type   | Amount  | Category    | Date" ascii //weight: 1
        $x_1_4 = "ChessLauncher.exe" wide //weight: 1
        $x_1_5 = "umdddssdgpc.dll" wide //weight: 1
        $x_1_6 = "SettingsUIHost_95t2e4dg8" wide //weight: 1
        $x_1_7 = "log_58742686" wide //weight: 1
        $x_1_8 = "asgiserver.live" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

