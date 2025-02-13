rule TrojanDownloader_MSIL_Dapato_E_2147657420_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Dapato.E"
        threat_id = "2147657420"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dapato"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 4f 00 00 00 20 48 00 00 00 58 fe 0e 0b 00 20 19 01 00 00 fe 0e 15 00 38 ?? ?? 00 00 3a ?? ?? 00 00 38 ?? ?? 00 00 20 fb 00 00 00 20 53 00 00 00 59}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 03 28 ?? ?? ?? ?? 04 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? ?? 73 ?? ?? ?? ?? 0b 07 17 6f ?? ?? ?? ?? ?? 07 16 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "set_UseShellExecute" ascii //weight: 1
        $x_1_4 = "set_Key" ascii //weight: 1
        $x_1_5 = "downexecute" ascii //weight: 1
        $x_1_6 = "hekRfkJMpt3huSTs8c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

