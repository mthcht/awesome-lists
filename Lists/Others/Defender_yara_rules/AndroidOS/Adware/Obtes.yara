rule Adware_AndroidOS_Obtes_A_349715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Obtes.A!MTB"
        threat_id = "349715"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Obtes"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {35 62 78 00 12 00 6e 30 ?? ?? 47 00 12 00 6e 30 ?? ?? 49 00 0c 00 1f 00 1a 00 6e 10 ?? ?? 00 00 0b 0a 13 00 2f 00 33 02 2b 00 84 a0 23 00 2c 00 12 1a 23 aa 2e 00 12 0b 4d 00 0a 0b 6e 30 ?? ?? 48 0a 21 0a d8 0a 0a fe 48 0a 00 0a 21 0b d8 0b 0b fe 12 1c 48 0c 00 0c 4f 0c 00 0b 12 1b 4f 0a 00 0b 54 ea ?? ?? 12 0b 71 20 ?? ?? b0 00 0c 00 4d 00 0a 02 d8 00 02 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

