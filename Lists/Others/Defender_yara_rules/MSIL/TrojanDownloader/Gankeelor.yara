rule TrojanDownloader_MSIL_Gankeelor_A_2147697167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Gankeelor.A"
        threat_id = "2147697167"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gankeelor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "w.weebly.com/uploads/3/7/4/0/37405427/data.dll" wide //weight: 4
        $x_1_2 = "GANKLR\\Desktop" ascii //weight: 1
        $x_1_3 = {49 6e 74 65 72 6e 65 74 5f 45 78 70 6c 6f 72 65 72 2e 4d 79 00 4d 79 43 6f 6d 70 75 74 65 72}  //weight: 1, accuracy: High
        $x_1_4 = "add_Shutdown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

