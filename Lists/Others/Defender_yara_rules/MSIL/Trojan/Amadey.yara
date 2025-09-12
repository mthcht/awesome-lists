rule Trojan_MSIL_Amadey_AA_2147843620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.AA!MTB"
        threat_id = "2147843620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 8e 69 17 59 8d ?? ?? ?? 01 0c 07 07 8e 69 17 59 91 0d 16 13 05 2b 20 08 11 05 07 11 05 91 06 11 05 06 8e 69 5d 91 09 58 20 ?? ?? ?? 00 5f 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 17 59 fe 02 16 fe 01 13 06 11 06 2d ce}  //weight: 1, accuracy: Low
        $x_1_2 = "ll.exe  -Command Add-" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_AB_2147843621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.AB!MTB"
        threat_id = "2147843621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nestlehosts.xyz" wide //weight: 1
        $x_1_2 = "DownloadData" wide //weight: 1
        $x_1_3 = "Modded params|Data0.bdt|All files|*.*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDCH_2147851144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDCH!MTB"
        threat_id = "2147851144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 6f 8e 00 00 0a 28 8f 00 00 0a 0c 08 73 90 00 00 0a 07 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_MA_2147852722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.MA!MTB"
        threat_id = "2147852722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 04 16 11 04 8e 69 28 ?? ?? 00 06 13 07 38 00 00 00 00 11 07 13 00 38 00 00 00 00 dd d6 00 00 00 00 11 06 3a 05 00 00 00 38 0c 00 00 00 11 06 28 ?? ?? 00 06 38 0a 00 00 00 38 06 00 00 00 38 ea ff ff ff 00 dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PSUS_2147852958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PSUS!MTB"
        threat_id = "2147852958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 00 06 03 28 ?? 05 00 06 6f ?? 00 00 0a 13 01 20 01 00 00 00 28 ?? 05 00 06 39 7b ff ff ff 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_NMA_2147853098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.NMA!MTB"
        threat_id = "2147853098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {12 02 02 8e 69 17 59 28 ?? 00 00 2b 00 08 13 07 20 ?? 00 00 00 38 ?? 00 00 00 00 28 ?? 00 00 0a 03 28 ?? 00 00 06 0a 20 ?? 00 00 00 38 ?? 00 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Geometri_Odev.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_NMA_2147853098_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.NMA!MTB"
        threat_id = "2147853098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 9a 13 04 11 04 6f ?? 00 00 0a 13 05 11 05 6f ?? 00 00 0a 02 6f ?? 00 00 0a 19 28 ?? 00 00 0a 2c 22 11 05 6f ?? 00 00 0a 28 38 00 00 06 02 6f 83 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "CoffeeToYaraAndJoeSandbox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PSUU_2147853117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PSUU!MTB"
        threat_id = "2147853117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 38 0b 00 00 00 26 20 05 00 00 00 38 9e ff ff ff 08 28 ?? ?? ?? 06 03 28 ?? 00 00 06 28 ?? 00 00 06 0b 20 02 00 00 00 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDJ_2147853226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDJ!MTB"
        threat_id = "2147853226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 09 16 11 09 8e 69 6f b4 00 00 0a 13 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_GP_2147853460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.GP!MTB"
        threat_id = "2147853460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 02 11 08 02 11 08 91 11 01 61 11 00 11 03 91 61 d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PABF_2147892093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PABF!MTB"
        threat_id = "2147892093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_2 = "Debugger Detected" wide //weight: 1
        $x_1_3 = "softbonesomfings.pdb" ascii //weight: 1
        $x_1_4 = "$ACC890C3-1016-1984-EDC0-4A866695C0BE" ascii //weight: 1
        $x_1_5 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_6 = "{11111-22222-50001-00001}" wide //weight: 1
        $x_1_7 = "KESAR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PSYR_2147892571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PSYR!MTB"
        threat_id = "2147892571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 17 00 00 06 6f 27 00 00 0a 6f 28 00 00 0a 6f 29 00 00 0a 0a 72 35 00 00 70 06 28 ?? 00 00 0a 72 43 00 00 70 72 47 00 00 70 6f 2b 00 00 0a 28 2c 00 00 0a 16 14 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_AMA_2147893172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.AMA!MTB"
        threat_id = "2147893172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 2b 06 07 28 06 00 00 06 06 6f 22 00 00 0a 25 0b 2d f0 de 0a 06 2c 06 06 6f 23 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_AMA_2147893172_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.AMA!MTB"
        threat_id = "2147893172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 2c eb 73 ?? 00 00 0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_AMA_2147893172_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.AMA!MTB"
        threat_id = "2147893172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 13 05 08 20 0b 01 00 00 33 0d 11 05 20 98 00 00 00 58 68 13 05 2b 0b 11 05 20 a8 00 00 00 58 68 13 05 06 11 05 6a 16 6f ?? 00 00 0a 26 11 04 06 6f ?? 00 00 0a 69 6f ?? 00 00 0a 11 04 02 7b 1a 00 00 04 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDM_2147894977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDM!MTB"
        threat_id = "2147894977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 1e 00 00 0a 02 7b 0c 00 00 04 6f 1f 00 00 0a 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PSUV_2147897053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PSUV!MTB"
        threat_id = "2147897053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 00 11 05 6f 9a 00 00 0a 13 06 38 1d 00 00 00 00 11 05 11 03 6f 9b 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PABV_2147897558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PABV!MTB"
        threat_id = "2147897558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 2f 00 20 01 00 00 00 20 a9 00 00 00 20 2a 00 00 00 58 9c 20 bf 00 00 00 38 08 2a 00 00 fe 0c 07 00 20 07 00 00 00 fe 0c 00 00 9c 20 4f 00 00 00 38 e8 29}  //weight: 1, accuracy: High
        $x_1_2 = {11 1d 11 30 19 58 11 19 20 00 00 00 ff 5f 1f 18 64 d2 9c 20 75 00 00 00 38 37 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PABW_2147897559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PABW!MTB"
        threat_id = "2147897559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 30 53 ef 67 20 e8 6f 2a ca 59 20 f7 0c 6a 17 61 20 bf ef ae 8a 61 7d 1b 04 00 04 20 41}  //weight: 1, accuracy: High
        $x_1_2 = {7e 2e 04 00 04 20 f2 06 ef bf 20 02 00 00 00 62 20 03 00 00 00 62 20 40 de e0 fd 61 7d 36 04 00 04 20 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_AAAU_2147899907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.AAAU!MTB"
        threat_id = "2147899907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 09 0d 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1f 0a 0d 11 04 6f ?? 00 00 0a 13 05 1f 0b 0d 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PTDI_2147901146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PTDI!MTB"
        threat_id = "2147901146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e b1 00 00 04 7e b0 00 00 04 28 ?? 01 00 06 14 fe 06 5f 00 00 06 73 30 00 00 0a 28 ?? 01 00 06 17 80 63 00 00 04 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDQ_2147901271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDQ!MTB"
        threat_id = "2147901271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 1c 5a 58 0a 08 17 58 0c 08 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDR_2147901765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDR!MTB"
        threat_id = "2147901765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 1f 30 28 05 00 00 2b 28 06 00 00 2b 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDT_2147901846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDT!MTB"
        threat_id = "2147901846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 00 16 11 00 8e 69 28 02 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDW_2147905154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDW!MTB"
        threat_id = "2147905154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 0c 07 11 0c 91 06 11 0c 06 8e 69 5d 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDV_2147905374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDV!MTB"
        threat_id = "2147905374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 02 11 06 28 01 00 00 2b 28 02 00 00 2b 16 11 06 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDX_2147906369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDX!MTB"
        threat_id = "2147906369"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 02 11 03 11 01 11 03 91 72 ?? ?? ?? ?? 28 03 00 00 0a 59 d2 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RPX_2147908192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RPX!MTB"
        threat_id = "2147908192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 78 00 00 04 09 91 13 04 11 04 16 31 2b 02 7b 7b 00 00 04 09 06 11 04 17 59 94 28 5f 00 00 06 9d 06 11 04 17 59 8f 50 00 00 01 25 4a 17 1f 10 11 04 59 1f 1f 5f 62 58 54 09 17 58 0d 09 02 7b 7a 00 00 04 32 b9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_NA_2147911279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.NA!MTB"
        threat_id = "2147911279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 13 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 25 28 ?? 00 00 06 28 ?? 00 00 0a 28 18 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Venomous.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDY_2147912267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDY!MTB"
        threat_id = "2147912267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 04 66 5f 03 66 04 5f 60 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_B_2147920438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.B!MTB"
        threat_id = "2147920438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 b5 a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 33 00 00 00 42 00 00 00 50 00 00 00 7e}  //weight: 4, accuracy: High
        $x_1_2 = "GetProcessById" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_RDFN_2147925295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.RDFN!MTB"
        threat_id = "2147925295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 02 00 00 2b 14 16 8d 13 00 00 01 6f 2b 00 00 0a 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_AYA_2147925547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.AYA!MTB"
        threat_id = "2147925547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$39a9277f-3cc8-4488-a5a2-f8f8f1422c75" ascii //weight: 3
        $x_2_2 = "ovrflw.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_MCF_2147947907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.MCF!MTB"
        threat_id = "2147947907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a2ec-2695fdf0888e" ascii //weight: 1
        $x_1_2 = {6b 6f 69 00 44 6f 77 6e 6c 6f}  //weight: 1, accuracy: High
        $x_1_3 = {57 94 02 28 49 03 00 00 00 fa 25 33 00 16 00 00 01}  //weight: 1, accuracy: High
        $x_1_4 = "DownloaderApp.am2.bin" ascii //weight: 1
        $x_1_5 = "LzmaDecoder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PGAD_2147948941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PGAD!MTB"
        threat_id = "2147948941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "$d4aca85c-7124-473d-a2ec-2695fdf0888e" ascii //weight: 1
        $x_1_2 = {6b 6f 69 00 44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e [0-8] 2e 72 65 73}  //weight: 1, accuracy: Low
        $x_1_4 = "LzmaDecoder" ascii //weight: 1
        $x_1_5 = "BitTreeDecoder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_PGAS_2147949543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.PGAS!MTB"
        threat_id = "2147949543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 08 20 b7 5c 8a 00 6a 5e 26 16 13 0a 2b 2b 11 05 11 0a 8f 18 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 1, accuracy: High
        $x_1_2 = {6b 6f 69 00 44 6f 77 6e 6c 6f 61 64 65 72 41 70 70 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "$d4aca85c-7124-473d-a2ec-2695fdf0888e" ascii //weight: 1
        $x_1_4 = {4d 61 74 68 00 4d 61 78 00 57 72 69 74 65 00 00 [0-4] 07 6b 00 6f 00 69 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 72 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? ?? ?? ?? ?? ?? 2e 6d 62 72 00 e2 80 ?? e2 80 ?? e2 80 ?? e2 80}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_MR_2147949839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.MR!MTB"
        threat_id = "2147949839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 0b 11 0c 91 13 0d 11 08 20 1f 3f 5e 00 5a 11 0d 58 13 08 11 0c 17 58 13 0c 11 0c 11 0b 8e 69 32 de}  //weight: 10, accuracy: High
        $x_5_2 = "$d4aca85c-7124-473d-a2ec-2695fdf0888e" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_CC_2147952110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.CC!MTB"
        threat_id = "2147952110"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b de 0a 06 2c 06 06 6f ?? 00 00 0a dc 07 2a}  //weight: 1, accuracy: Low
        $x_3_2 = {13 38 12 38 73 ?? 00 00 0a 13}  //weight: 3, accuracy: Low
        $x_3_3 = {d2 28 54 00 00 0a 26 11 ?? 28 62 00 00 0a 28 66 00 00 0a 13}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_SPYT_2147952138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.SPYT!MTB"
        threat_id = "2147952138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {63 d1 13 17 11 15 11 09 91 13 2a 11 15 11 09 11 24 11 2a 61 11 1c 19 58 61 11 2f 61 d2 9c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Amadey_SLBE_2147952158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Amadey.SLBE!MTB"
        threat_id = "2147952158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 2d 0b 73 ?? 00 00 06 28 ?? 00 00 0a 2a 20 ?? ?? ?? ?? ?? ?? 00 00 06 0c 20 ?? ?? ?? ?? ?? ?? 00 00 06 0d 20 ?? ?? ?? ?? ?? ?? 00 00 06 13 04 1f 24 28 19 00 00 0a 25 08 28 ?? 00 00 0a 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

