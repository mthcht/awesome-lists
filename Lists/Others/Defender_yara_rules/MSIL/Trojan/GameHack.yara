rule Trojan_MSIL_GameHack_AB_2147793978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GameHack.AB!MTB"
        threat_id = "2147793978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GameHack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 0d 1c 62 13 0e 16 13 0f 38 3e 00 00 00 06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d}  //weight: 10, accuracy: High
        $x_3_2 = "Injector" ascii //weight: 3
        $x_3_3 = "Zeus" ascii //weight: 3
        $x_3_4 = "DllInjector" ascii //weight: 3
        $x_3_5 = "bInject" ascii //weight: 3
        $x_3_6 = "Furky" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

