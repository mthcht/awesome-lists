rule Trojan_MSIL_BadJoke_MA_2147809187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadJoke.MA!MTB"
        threat_id = "2147809187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Can't close me ;)" wide //weight: 1
        $x_1_2 = "troll" ascii //weight: 1
        $x_1_3 = "timer1_Tick" ascii //weight: 1
        $x_1_4 = "SetDesktopLocation" ascii //weight: 1
        $x_1_5 = "a0f0b5ce-27da-4143-b2ae-4b7197df46a7" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BadJoke_KAA_2147903844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadJoke.KAA!MTB"
        threat_id = "2147903844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 11 07 61 1f 0a 63 61 5a 11 07 5a d2 9c 11 07 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BadJoke_PZML_2147937213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadJoke.PZML!MTB"
        threat_id = "2147937213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {00 02 7b 05 00 00 04 6f 19 00 00 0a 00 02 28 22 00 00 0a 6f 23 00 00 0a 73 24 00 00 0a 6f 25 00 00 0a 00 28 26 00 00 0a 0d 12 03 28 27 00 00 0a 0a 28 26 00 00 0a 0d 12 03 28 28 00 00 0a 0b 7e 29 00 00 0a 28 02 00 00 06 0c 08 28 2a 00 00 0a 13 04 00 11 04 02 7b 02 00 00 04 06 07 6f 2b 00 00 0a 00 00 de 0d}  //weight: 3, accuracy: High
        $x_3_2 = {00 02 7b 06 00 00 04 6f 19 00 00 0a 00 02 73 1a 00 00 0a 7d 01 00 00 04 28 01 00 00 06 0a 06 28 02 00 00 06 0b 28 1d 00 00 0a 6f 1e 00 00 0a 13 04 12 04 28 1f 00 00 0a 0c 28 1d 00 00 0a 6f 1e 00 00 0a 13 04 12 04 28 20 00 00 0a}  //weight: 3, accuracy: High
        $x_2_3 = "$25e1efc0-6429-4e72-a542-d6fe0f5a0122" ascii //weight: 2
        $x_1_4 = "gdi_test.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BadJoke_SLC_2147941273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BadJoke.SLC!MTB"
        threat_id = "2147941273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BadJoke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1c 72 86 04 00 70 a2 28 27 00 00 0a 0b 06 07 28 28 00 00 0a 00 06 28 29 00 00 0a 26 72 98 04 00 70 72 b0 04 00 70 72 d2 04 00 70 72 e6 04 00 70 28 04 00 00 06 00 02 28 2a 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

