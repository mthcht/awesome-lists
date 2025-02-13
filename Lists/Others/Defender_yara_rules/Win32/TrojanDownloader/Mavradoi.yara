rule TrojanDownloader_Win32_Mavradoi_A_2147692783_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mavradoi.A"
        threat_id = "2147692783"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mavradoi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "DB6BFC7BFD629AD42EC14BACD76D88E80C145DFD111C52A4C42" ascii //weight: 4
        $x_4_2 = "4CDB6D8BED728AE41E313A9BC67ED97ED9064FEF032AA037913" ascii //weight: 4
        $x_4_3 = "43D26492D41B658FE07687C814C1054B8EB2122AC569EF66E26" ascii //weight: 4
        $x_3_4 = "28167085D470DF79E9127687CD064E9C3DD808331707" ascii //weight: 3
        $x_3_5 = "w.artplic.com.br/fancybox/count.php" ascii //weight: 3
        $x_2_6 = "A3AEB63FB93846B732" ascii //weight: 2
        $x_2_7 = "27D47CCC0F4C82C113CE" ascii //weight: 2
        $x_2_8 = "0D19CD055EE770E518CA73E06CF755F4" ascii //weight: 2
        $x_2_9 = "E251C7C0C7034B8AC77DA0F6538C35" ascii //weight: 2
        $x_2_10 = "12C57095CC0C4B82" ascii //weight: 2
        $x_2_11 = "E917C312B3114790C76295EA" ascii //weight: 2
        $x_2_12 = "31C57ED5084A94314BE7114E" ascii //weight: 2
        $x_2_13 = "DF827984KD88G434F5D" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Mavradoi_B_2147692788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mavradoi.B"
        threat_id = "2147692788"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mavradoi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "u76gvfDbuKvCtuLduK6tt7zuxfDjtKrpv1nCq1vsuKvovfzfuLnjt79CuLvo" ascii //weight: 4
        $x_4_2 = "u76gvfDbuKvCtwLJCM6ZB8z7xfDPBMrVD2" ascii //weight: 4
        $x_2_3 = "Cq2vYCMvUDfzLCNnPB83" ascii //weight: 2
        $x_3_4 = "/m2pr.org/material/galeria_imagens/99/adm/images/inff.php" ascii //weight: 3
        $x_2_5 = "zgvZA2rVCdi" ascii //weight: 2
        $x_2_6 = "uhjVz2jHBuzPBgvZrgLY" ascii //weight: 2
        $x_2_7 = "uhjVzhvJDe9HBwu" ascii //weight: 2
        $x_2_8 = "r7jqtfvhsu3" ascii //weight: 2
        $x_2_9 = "kIOQie1HBgrPDg5GAw9ZDgfSywrVicOQkG" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

