rule Trojan_MSIL_Arkei_NE_2147830483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Arkei.NE!MTB"
        threat_id = "2147830483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Arkei"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 72 01 00 00 70 0a 72 ?? 00 00 70 0b 28 01 00 00 06 0c 08 16 28 02 00 00 06 26 73 0f 00 00 0a 0d 09 06 07 6f 10 00 00 0a 00 20 dc 05 00 00 28 11 00 00 0a 00 00 00 20 b3 15 00 00 28 11 00 00 0a 00 28 04 00 00 06 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "/Cstart C:\\Windows\\Temp\\" wide //weight: 1
        $x_1_3 = "cmd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

