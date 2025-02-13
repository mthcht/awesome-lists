rule Trojan_MSIL_Fbompro_A_2147655703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fbompro.A"
        threat_id = "2147655703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fbompro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 7b 13 00 00 04 72 ?? ?? 00 70 28 66 00 00 0a 28 9e 00 00 0a 2c 1a 02 7b 13 00 00 04 72 ?? ?? 00 70 28 66 00 00 0a 28 9e 00 00 0a 16 fe 01}  //weight: 1, accuracy: Low
        $x_1_2 = {17 8d 86 00 00 01 13 0e 11 0e 16 1f 7c 9d 11 0e 6f c9 00 00 0a 0a 06 8e 69 19 fe 01 16 fe 01 13 0d 11 0d 3a 42}  //weight: 1, accuracy: High
        $x_1_3 = "wc_DownloadFileCompleted" ascii //weight: 1
        $x_1_4 = "KillFBPromo" ascii //weight: 1
        $x_1_5 = "ffrun" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

