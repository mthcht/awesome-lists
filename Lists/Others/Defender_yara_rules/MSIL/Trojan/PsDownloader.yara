rule Trojan_MSIL_PsDownloader_CXA_2147842737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownloader.CXA!MTB"
        threat_id = "2147842737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 00 28 02 00 00 2b 06 14 17 8d ?? ?? ?? ?? 25}  //weight: 5, accuracy: Low
        $x_5_2 = {28 1c 00 00 0a 7e ?? ?? ?? ?? 02 1a 58 08 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? a5 ?? ?? ?? ?? 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownloader_PSWL_2147889430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownloader.PSWL!MTB"
        threat_id = "2147889430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 ac 03 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 0b 08 28 ?? 00 00 0a 2d 10 08 11 0b 28 ?? 00 00 0a 16 13 18 dd 1e 03 00 00 11 13 7b 2c 00 00 04 11 0b 6f ?? 00 00 0a 26 14 13 0c 72 cf 07 00 70 73 c0 00 00 0a 13 0d 11 07 13 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

