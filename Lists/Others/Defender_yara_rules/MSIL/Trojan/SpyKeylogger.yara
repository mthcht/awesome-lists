rule Trojan_MSIL_SpyKeylogger_A_2147746071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyKeylogger.A!MTB"
        threat_id = "2147746071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 72 dd 00 00 70 6f 1d 00 00 0a 26 08 16 08 6f 1a 00 00 0a 6f 1b 00 00 0a 26 08 07 6f 1d 00 00 0a 26 11 06 11 05 08 28 03 00 00 06 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyKeylogger_AMAB_2147852931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyKeylogger.AMAB!MTB"
        threat_id = "2147852931"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 4e 11 11 11 13 8f ?? ?? ?? 02 71 ?? ?? ?? 02 13 0b 11 0a 12 0b 7b ?? ?? ?? 04 28 ?? 00 00 0a 13 0a 12 0b 7b ?? ?? ?? 04 1f 20 5f 2c 0e 11 0a 72 ?? ?? ?? 70 28 ?? 00 00 0a 13 0a 11 0a 72 ?? ?? ?? 70 28 ?? 00 00 0a 13 0a 11 13 17 58 13 13 11 13 11 0f 32 ac 7e ?? ?? ?? 04 7e ?? ?? ?? 04 11 0a 28 ?? 00 00 0a 20 e8 03 00 00 28 ?? 00 00 0a 06}  //weight: 1, accuracy: Low
        $x_1_2 = {13 05 11 06 72 ?? ?? ?? 70 6f 1d 00 00 0a 26 08 16 08 6f ?? 00 00 0a 6f ?? 00 00 0a 26 08 07 6f ?? 00 00 0a 26 11 06 11 05 08 28 ?? ?? ?? 06 07}  //weight: 1, accuracy: Low
        $x_1_3 = "Clipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

