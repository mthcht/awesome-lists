rule Trojan_MSIL_TheTheif_CSTY_2147847235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TheTheif.CSTY!MTB"
        threat_id = "2147847235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TheTheif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 8d 01 00 00 01 13 05 11 05 16 28 ?? ?? ?? ?? a2 11 05 17 72 ?? ?? ?? ?? a2 11 05 18 73 ?? ?? ?? ?? 1f 0a 20 ?? ?? ?? ?? 6f ?? ?? ?? ?? 8c ?? ?? ?? ?? a2 11 05 19 72 ?? ?? ?? ?? a2 11 05 28 ?? ?? ?? ?? 0d 08 06 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 09 07 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? de 03 26 de 00 08 28 09 00 00 0a 26 de 03 26 de 00 09 28 09 00 00 0a 26 de 03}  //weight: 5, accuracy: Low
        $x_1_2 = "sqls8.exe" wide //weight: 1
        $x_1_3 = "drivEn8.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

