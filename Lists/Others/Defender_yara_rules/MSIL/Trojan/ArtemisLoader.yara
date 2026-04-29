rule Trojan_MSIL_ArtemisLoader_AAA_2147968036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArtemisLoader.AAA!AMTB"
        threat_id = "2147968036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArtemisLoader"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "https://builder.pp.ru/" ascii //weight: 5
        $x_1_2 = "Invoke" ascii //weight: 1
        $x_5_3 = "http://f0572755.xsph.ru/4WQKY3X790.exe" wide //weight: 5
        $x_5_4 = "http://f0572755.xsph.ru/EKEJOPR2JE.exe" wide //weight: 5
        $x_5_5 = "https://cdn.discordapp.com/attachments/879768168590106726/880783592572198983/1829612076.exe" wide //weight: 5
        $x_5_6 = "http://83.97.20.139/1.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

