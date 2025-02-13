rule TrojanSpy_AndroidOS_Handda_A_2147819329_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Handda.A!MTB"
        threat_id = "2147819329"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Handda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 03 08 00 23 31 ?? ?? 12 00 21 12 34 20 03 00 11 01 22 02 ?? ?? 16 04 ff 00 c0 64 70 30 ?? ?? 42 05 6e 10 ?? ?? 02 00 0a 02 4f 02 01 00 c4 36 d8 00 00 01}  //weight: 1, accuracy: Low
        $x_1_2 = {1a 01 00 00 71 10 ?? ?? 05 00 0c 02 21 20 d8 00 00 ff 01 04 07 10 01 41 3b 01 ?? ?? 11 00 22 03 ?? ?? 71 10 ?? ?? 00 00 0c 00 70 20 ?? ?? 03 00 48 00 02 01 d5 00 ff 00 6e 20 ?? ?? 03 00 0c 00 6e 10 ?? ?? 00 00 0c 00 3d 01 ?? ?? 22 03 ?? ?? 71 10 ?? ?? 00 00 0c 00 70 20 ?? ?? 03 00 1a 00 ?? ?? 6e 20 ?? ?? 03 00 0c 00 6e 10 ?? ?? 00 00 0c 00 d8 01 01 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Handda_AB_2147833330_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Handda.AB!MTB"
        threat_id = "2147833330"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Handda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "system/lib pm get-install-location" ascii //weight: 1
        $x_1_2 = {13 05 08 00 04 82 23 50 ?? ?? 12 01 21 04 34 41 03 00 11 00 22 04 ?? ?? 16 06 ff 00 c0 26 70 30 ?? ?? 64 07 6e 10 ?? ?? 04 00 0a 04 4f 04 00 01 c4 52 d8 01 01 01}  //weight: 1, accuracy: Low
        $x_1_3 = {1a 02 00 00 71 10 ?? ?? 05 00 0c 00 21 03 d8 01 03 ff 3b 01 ?? ?? 11 02 22 03 ?? ?? 71 10 ?? ?? 02 00 0c 04 70 20 ?? ?? 43 00 48 04 00 01 d5 44 ff 00 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 02 3d 01 ?? ?? 22 03 ?? ?? 71 10 ?? ?? 02 00 0c 04 70 20 ?? ?? 43 00 1a 04 ?? ?? 6e 20 ?? ?? 43 00 0c 03 6e 10 ?? ?? 03 00 0c 02 d8 01 01 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

