rule TrojanDownloader_Win32_Bangkgrob_A_2147692732_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bangkgrob.A"
        threat_id = "2147692732"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bangkgrob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "p://fitapreta.com" ascii //weight: 4
        $x_4_2 = "index.php/downloadcount/fugitivo-100" ascii //weight: 4
        $x_4_3 = "w.trajanoalmeida.com.br" ascii //weight: 4
        $x_2_4 = "/Clientes/Instal.bck" ascii //weight: 2
        $x_1_5 = "/old.bck" ascii //weight: 1
        $x_1_6 = "/vista.bck" ascii //weight: 1
        $x_1_7 = "/Task.bck" ascii //weight: 1
        $x_1_8 = "/xp.bck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

