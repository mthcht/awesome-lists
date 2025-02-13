rule TrojanDownloader_Win32_Bloropac_A_2147653536_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bloropac.A"
        threat_id = "2147653536"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bloropac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "to=newpharmsb@gmail.com" wide //weight: 2
        $x_2_2 = "to=sapoboiazul10@gmail.com" wide //weight: 2
        $x_2_3 = "to=novoaviso2011@gmail.com" wide //weight: 2
        $x_1_4 = "dowbleoor.dat" wide //weight: 1
        $x_1_5 = "C:\\Boot.exe" wide //weight: 1
        $x_1_6 = "subject=[+][1][T][O][N][T][O]-" wide //weight: 1
        $x_1_7 = "message=infectado" wide //weight: 1
        $x_1_8 = "IPA\" /d C:\\Dongle.exe" ascii //weight: 1
        $x_1_9 = "Unistall.pac" ascii //weight: 1
        $x_1_10 = "Windows\\Boot.exe" wide //weight: 1
        $x_1_11 = "SUROWND" wide //weight: 1
        $x_2_12 = "sbmarketingepropaganda.com/rename.txt" ascii //weight: 2
        $x_2_13 = "vigitronic.com/modules/gh.php" ascii //weight: 2
        $x_2_14 = "187.33.4.75/sub/post" ascii //weight: 2
        $x_2_15 = "omenex.com/images/total_visitas.php" ascii //weight: 2
        $x_2_16 = "badminton37.fr/images/gh.php" ascii //weight: 2
        $x_2_17 = "avalonglobalsolutions.com/tmp/gh.php" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bloropac_B_2147653553_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bloropac.B"
        threat_id = "2147653553"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bloropac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "to=newpharmsb@gmail.com" ascii //weight: 1
        $x_1_2 = "dowbleoor.dat" ascii //weight: 1
        $x_1_3 = "subject=[+][1][T][O][N][T][O]-" ascii //weight: 1
        $x_1_4 = "message=infectado" ascii //weight: 1
        $x_1_5 = "C:\\Boot.exe" ascii //weight: 1
        $x_1_6 = "IPA\" /d C:\\Dongle.exe" ascii //weight: 1
        $x_1_7 = "latabledesdombes.com/plugins" ascii //weight: 1
        $x_1_8 = "contador/gh.php" ascii //weight: 1
        $x_2_9 = "187.33.2.14/alcalina.dat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

