rule Trojan_MSIL_Bodegun_AMKD_2147832249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bodegun.AMKD!MTB"
        threat_id = "2147832249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0b 16 0c 2b 62 07 08 9a 0d 00 09 6f ?? ?? ?? 0a 13 05 12 05 fe 16 16 00 00 01 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bodegun_MBJZ_2147893084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bodegun.MBJZ!MTB"
        threat_id = "2147893084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 17 20 00 10 00 00 6f ?? 00 00 0a fe 01 13 10 11 10 2c b9}  //weight: 1, accuracy: Low
        $x_1_2 = "ef-77b2-431f-93e0-f313d48fec4e" ascii //weight: 1
        $x_1_3 = "virusthing2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bodegun_KAA_2147895802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bodegun.KAA!MTB"
        threat_id = "2147895802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 1f 00 06 72 ?? 00 00 70 02 07 91 8c ?? 00 00 01 28 ?? 00 00 0a 6f ?? 00 00 0a 26 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d d7}  //weight: 5, accuracy: Low
        $x_5_2 = "http://pwn.uphero.com/" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bodegun_PGB_2147936853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bodegun.PGB!MTB"
        threat_id = "2147936853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bodegun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hi, im a mosquito, a mosquito that currently infected your computer." ascii //weight: 1
        $x_4_2 = "would you like to stop the infection?" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

