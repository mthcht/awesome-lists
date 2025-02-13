rule TrojanDownloader_MSIL_Minecru_A_2147716343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Minecru.A!bit"
        threat_id = "2147716343"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Minecru"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 28 22 00 00 0a 06 6f 23 00 00 0a 6b 5a 22 00 00 ?? ?? 59 6b 6c 28 1e 00 00 0a b7 6f 24 00 00 0a 28 25 00 00 0a 28 26 00 00 0a 0b 09 17 d6 0d 09 1f ?? 31 ca}  //weight: 1, accuracy: Low
        $x_1_2 = "QWERTYUIOPASDFGHJKLZXCVBNM1234567890qazxswedcvfrtgbnhyujmkiolp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

