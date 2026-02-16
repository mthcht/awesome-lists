rule Trojan_MSIL_Marte_PQHH_2147928001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marte.PQHH!MTB"
        threat_id = "2147928001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DISABLE_FACTORY_RESET" ascii //weight: 3
        $x_2_2 = "reagentc.exe /disable" ascii //weight: 2
        $x_2_3 = "DISABLE_DEFENDER" ascii //weight: 2
        $x_1_4 = "michael-currently.gl.at.ply.gg" ascii //weight: 1
        $x_1_5 = "fodhelper.exe" ascii //weight: 1
        $x_1_6 = "Software\\Classes\\ms-settings\\Shell\\Open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marte_AB_2147951421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marte.AB!MTB"
        threat_id = "2147951421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 0b 06 07 16 1a 6f 1d 00 00 0a 26 07 16 28 1c 00 00 0a 0c 06 16 73 cd 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marte_MK_2147962308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marte.MK!MTB"
        threat_id = "2147962308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_25_1 = {25 19 63 0a 1d 5f 2c 04 06 17 58 0a 06 8d 8d 00 00 01 0b 06 19 5f 0c 08 2d 02 1a 0c 16 0d 02 7b 01 00 00 04}  //weight: 25, accuracy: High
        $x_10_2 = {06 17 59 8f 8b 00 00 01 25 4b 09 60 54 15 1f 20 07 59 1f 1f 5f 64 0d 02 7b 02 00 00 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Marte_SX_2147963102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Marte.SX!MTB"
        threat_id = "2147963102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marte"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {fe 16 0d 00 00 01 6f ?? 00 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? 00 00 0a 16 1f 0a 6f ?? 00 00 0a 13 ?? 72 ?? ?? 00 70 28 ?? 00 00 0a 13}  //weight: 20, accuracy: Low
        $x_10_2 = "{{\"GUID\":\"{0}\",\"Type\":{1},\"Meta\":\"{2}\",\"IV\":\"{3}\",\"EncryptedMessage\":\"{4}\",\"HMAC\":\"{5}\"}}" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

