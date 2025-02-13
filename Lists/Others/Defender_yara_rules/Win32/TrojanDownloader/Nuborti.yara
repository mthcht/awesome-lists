rule TrojanDownloader_Win32_Nuborti_A_2147683784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Nuborti.A"
        threat_id = "2147683784"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuborti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "160"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "byvOlk\\Desktop\\[Unicorn-Botnet]" wide //weight: 100
        $x_50_2 = "HottterxWsn2" ascii //weight: 50
        $x_20_3 = "Pharming Failed" wide //weight: 20
        $x_20_4 = "Spread USB/P2P Successful" wide //weight: 20
        $x_20_5 = "Stealer Failed" wide //weight: 20
        $x_10_6 = "winbtservs.com" wide //weight: 10
        $x_10_7 = "hpleneservas.com" wide //weight: 10
        $x_10_8 = "parasetmolexis.com" wide //weight: 10
        $x_10_9 = "nod32valesverga.com" wide //weight: 10
        $x_10_10 = "Bot.php" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 3 of ($x_20_*) and 5 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_20_*) and 4 of ($x_10_*))) or
            ((1 of ($x_100_*) and 2 of ($x_20_*) and 2 of ($x_10_*))) or
            ((1 of ($x_100_*) and 3 of ($x_20_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_10_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 1 of ($x_20_*))) or
            (all of ($x*))
        )
}

