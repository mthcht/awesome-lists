rule TrojanDownloader_MSIL_Trolex_A_2147830884_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Trolex.A!MTB"
        threat_id = "2147830884"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trolex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 93 0c 08 1f 61 32 ?? 08 1f 7a 30 ?? 08 1f 6d 31 ?? 08 1f 0d 59 0c 2b ?? 08 1f 0d 58 0c 2b ?? 08 1f 41 32 ?? 08 1f 5a 30 ?? 08 1f 4d 31 ?? 08 1f 0d 59 0c 2b ?? 08 1f 0d 58 0c 06 07 08 d1 9d 07 17 58 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "cmd /c certutil -decode" wide //weight: 1
        $x_1_3 = "/create /sc MINUTE /mo 3 /tn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

