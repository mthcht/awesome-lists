rule TrojanDownloader_MSIL_Bassit_A_2147696964_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Bassit.A"
        threat_id = "2147696964"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bassit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 6b 61 6b 61 72 6f 74 74 6f 7c [0-128] 2f 2f 3a [0-1] 70 74 74 68}  //weight: 1, accuracy: Low
        $x_1_2 = {74 00 65 00 6d 00 70 00 ?? ?? 73 00 74 00 61 00 72 00 ?? ?? 5c 00 ?? ?? 44 00 41 00 54 00 41 00 ?? ?? 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\kakarotto\\Desktop\\new server\\builder\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

