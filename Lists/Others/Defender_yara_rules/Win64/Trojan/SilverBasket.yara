rule Trojan_Win64_SilverBasket_B_2147937501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverBasket.B!dha"
        threat_id = "2147937501"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverBasket"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 58 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5d 58 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {f0 55 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 4a 00 00 80 00 00 00 10 00 00 00 10 00 00 00 10 00 00 00 e0 00 00 00 e8 03 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win64_SilverBasket_A_2147938207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverBasket.A!dha"
        threat_id = "2147938207"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverBasket"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\SkyPDF\\ClsSrv.inf" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\SkyPDF\\PDUDrv.blf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

