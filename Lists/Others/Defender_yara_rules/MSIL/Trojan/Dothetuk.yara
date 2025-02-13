rule Trojan_MSIL_Dothetuk_B_2147797794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.B!MTB"
        threat_id = "2147797794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_SPFDrZIEU9rHR5ToV9ujgGhB4N5" ascii //weight: 1
        $x_1_2 = "_I4RBe8ty35SH3wKmbfbFwp6cv7B" ascii //weight: 1
        $x_1_3 = "_pa04Hp38fHHjJfOEAET1kFOvL7E" ascii //weight: 1
        $x_1_4 = "_G9eB0PcZy5aN1qBGE5atqUWGimE" ascii //weight: 1
        $x_1_5 = "_q3clZIbI2e29lkJupMzaQHZDIgJ" ascii //weight: 1
        $x_1_6 = "_xCOrqbsQXQnq8WR2Y0cCXDa0bDj" ascii //weight: 1
        $x_1_7 = "_RP92JkvYq7AaKC7ukOH6rxoXGbj" ascii //weight: 1
        $x_1_8 = "_4CKx7Eyb5Xt9mtXmlSX0U0Ulean" ascii //weight: 1
        $x_1_9 = "_T1HycSPChkiecherNetSb1UHPVu" ascii //weight: 1
        $x_1_10 = "$4fb28d5b-0d8e-4144-b1f7-62dad0f41bb9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_AD_2147838189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.AD!MTB"
        threat_id = "2147838189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 07 08 09 16 20 ff 00 00 00 6f ?? ?? ?? 0a b4 9c 08 17 d6 0c 08 20 db ff 00 00 31 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_ADH_2147845007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.ADH!MTB"
        threat_id = "2147845007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 0e 2b 30 00 00 08 11 0c 11 0e 8f 14 00 00 02 7c 2c 00 00 04 7b 22 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 de 05 26 00 00 de 00 00 11 0e 17 58 13 0e 11 0e 6a 11 07 6e fe 04 13 0f 11 0f 2d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_ADH_2147845007_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.ADH!MTB"
        threat_id = "2147845007"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 03 07 05 0e 04 73 09 00 00 0a 0d 09 0e 06 1e 5b 6f ?? ?? ?? 0a 13 04 28 ?? ?? ?? 0a 13 05 11 05 17 6f ?? ?? ?? 0a 08 8e 69 8d 0a 00 00 01 13 06 16 13 07 11 05 11 04 06 6f ?? ?? ?? 0a 13 08 08}  //weight: 2, accuracy: Low
        $x_1_2 = "BitCoreMiracles.exe" wide //weight: 1
        $x_1_3 = "BumGConsoleAPP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_GIC_2147846152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.GIC!MTB"
        threat_id = "2147846152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 67 00 00 70 28 ?? ?? ?? 06 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 72 e5 00 00 70 7e 1c 00 00 0a 6f 1d 00 00 0a 28 ?? ?? ?? 0a 0c de 17 26 20 d0 07 00 00 28 ?? ?? ?? 0a de 00 06 17 58 0a 06 1b 32 bd}  //weight: 10, accuracy: Low
        $x_1_2 = "aocgamestudio.xyz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_AM_2147900749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.AM!MTB"
        threat_id = "2147900749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 08 06 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0b de}  //weight: 4, accuracy: Low
        $x_1_2 = "SELECT * FROM AntivirusProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_NN_2147902270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.NN!MTB"
        threat_id = "2147902270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 5e d1 0d 11 0e 11 06 5a 11 08 58 20 ?? ?? ?? ?? 5e d1 13 06 11 0b 17 58 13 0b 1f 11 13 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_LL_2147902271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.LL!MTB"
        threat_id = "2147902271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 58 5e d2 61 d2 81 31 ?? ?? ?? 11 0c 11 07 5a 11 08 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dothetuk_GZZ_2147906552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dothetuk.GZZ!MTB"
        threat_id = "2147906552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dothetuk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 72 43 00 00 70 28 ?? ?? ?? 0a 72 75 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 13 01}  //weight: 5, accuracy: Low
        $x_5_2 = {11 03 11 01 16 73 0e 00 00 0a 13 09 20 00 00 00 00}  //weight: 5, accuracy: High
        $x_1_3 = "kMNkwTkm4lUxOdeuJ5QiGA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

