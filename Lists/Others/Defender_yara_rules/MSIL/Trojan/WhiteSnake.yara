rule Trojan_MSIL_WhiteSnake_PA_2147845557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.PA!MTB"
        threat_id = "2147845557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 00 00 fe 09 00 00 fe 0c 01 00 6f ?? ?? ?? 0a fe 09 01 00 fe 09 02 00 28 ?? ?? ?? 0a fe 0c 01 00 fe 09 01 00 fe 09 02 00 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d1 fe 0e 02 00 fe 0d 02 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 00 00 fe 0c 01 00 20 01 00 00 00 58 fe 0e 01 00 fe 0c 01 00 fe 09 00 00 6f ?? ?? ?? 0a 3f 8e ff ff ff fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_PA_2147845557_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.PA!MTB"
        threat_id = "2147845557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 28 ?? ?? ?? ?? fe 09 01 00 fe 0c 02 00 fe 0c 01 00 5d 6f ?? ?? ?? ?? fe 0e 03 00 72 01 00 00 70 28 ?? ?? ?? ?? fe 0c 00 00 fe 09 00 00 fe 0c 02 00 6f ?? ?? ?? ?? fe 0c 03 00 61 d1 fe 0e 04 00 fe 0d 04 00 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? fe 0e 00 00 72 01 00 00 70 28 ?? ?? ?? ?? fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 6f ?? ?? ?? ?? 3f 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_PB_2147845558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.PB!MTB"
        threat_id = "2147845558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WhiteSnake\\Stub\\Windows\\obj\\Release\\DarkGay.pdb" ascii //weight: 1
        $x_1_2 = "[ANTIVM]" wide //weight: 1
        $x_1_3 = "[BEACON]" wide //weight: 1
        $x_1_4 = "vmware" wide //weight: 1
        $x_1_5 = "VMXh" wide //weight: 1
        $x_1_6 = "vbox" wide //weight: 1
        $x_1_7 = "Grabber\\Wallets\\" wide //weight: 1
        $x_1_8 = "DEL /F /S /Q /A" wide //weight: 1
        $x_1_9 = "Foxmail" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_MA_2147846957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.MA!MTB"
        threat_id = "2147846957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 ad 11 ae 11 ac 11 ae 94 11 ac 11 ae 94 59 9e 00 11 ae 17 58 13 ae 11 ae 11 ac 8e 69 fe 04 13 af 11 af 3a d7 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {57 bf a2 3d 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9c}  //weight: 1, accuracy: High
        $x_1_3 = "82274210-63fb-4444-9839-9275a4fb9484" ascii //weight: 1
        $x_1_4 = "_bvT3uckhLx10s.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_GAI_2147847065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.GAI!MTB"
        threat_id = "2147847065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0d 9e 06 06 08 94 06 09 94 58 20 00 01 00 00 5d 94 13 0e 11 04 11 0c 02 11 0c 91 11 0e 61 28 ?? 00 00 0a 9c 00 11 0c 17 58 13 0c 11 0c 02 8e 69 fe 04 13 0f 11 0f 3a}  //weight: 3, accuracy: Low
        $x_2_2 = "pornhub.com" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_AWI_2147847582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.AWI!MTB"
        threat_id = "2147847582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 09 01 00 fe 0c 02 00 fe 0c 01 00 5d 6f ?? ?? ?? 0a fe 0e 03 00 fe 0c 00 00 fe 09 00 00 fe 0c 02 00 6f ?? ?? ?? 0a fe 0c 03 00 61 d1 fe 0e 04 00 fe 0d 04 00 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_MBEA_2147848647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.MBEA!MTB"
        threat_id = "2147848647"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 7e 46 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 00 28 ?? 00 00 06 00 00 00 11 05 16 fe 01 13 07 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_PC_2147849068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.PC!MTB"
        threat_id = "2147849068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 09 00 00 fe 0c 02 00 6f ?? ?? ?? ?? fe 0e 03 00 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? fe 0e 04 00 fe 0c 01 00 fe 0c 03 00 fe 0c 04 00 61 d1 fe 0e 05 00 fe 0d 05 00 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? fe 0e 01 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 09 00 00 6f ?? ?? ?? ?? 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_DH_2147852522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.DH!MTB"
        threat_id = "2147852522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 0c 07 00 20 00 01 00 00 5d fe 0e 02 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 03 00 58 20 00 01 00 00 5d fe 0e 03 00 fe 0c 04 00 fe 0c 02 00 94 fe 0e 01 00 fe 0c 04 00 fe 0c 02 00 fe 0c 04 00 fe 0c 03 00 94 9e fe 0c 04 00 fe 0c 03 00 fe 0c 01 00 9e fe 0c 00 00 fe 09 00 00 fe 0c 07 00 ?? ?? ?? ?? ?? fe 0c 04 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 04 00 fe 0c 03 00 94 58 20 00 01 00 00 5d 94 61 d1 ?? ?? ?? ?? ?? 26 fe 0c 07 00 20 01 00 00 00 58 fe 0e 07 00 fe 0c 07 00 fe 09 00 00 ?? ?? ?? ?? ?? 3f 57 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_RZ_2147889338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.RZ!MTB"
        threat_id = "2147889338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 08 03 11 08 03 8e 69 5d 91 9e 00 11 08 17 58 13 08 11 08 20 00 01 00 00 fe 04 13 09 11 09 3a da ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {09 06 08 94 58 07 08 94 58 20 00 01 00 00 5d 0d 06 08 94 13 0a 06 08 06 09 94 9e 06 09 11 0a 9e 00 08 17 58 0c 08 20 00 01 00 00 fe 04 13 0b 11 0b 3a c9 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_MBJX_2147893001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.MBJX!MTB"
        threat_id = "2147893001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 04 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 04 00 fe 0c 03 00 94 58 20 00 01 00 00 5d 94 61 d1 fe 0e 09 00 fe 0d 09 00}  //weight: 1, accuracy: High
        $x_1_2 = "93d0-e3183ff2a26d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_RDA_2147894065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.RDA!MTB"
        threat_id = "2147894065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0c 04 00 fe 0c 04 00 fe 0c 02 00 94 fe 0c 04 00 fe 0c 03 00 94 58 20 00 01 00 00 5d 94 61 d1 fe 0e 09 00 fe 0d 09 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_RDB_2147895317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.RDB!MTB"
        threat_id = "2147895317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8df03461-112d-4387-a90d-525db3cdbf75" ascii //weight: 1
        $x_1_2 = "_GasP4oFjYQcwE" ascii //weight: 1
        $x_1_3 = "rstrtmgr.dll" ascii //weight: 1
        $x_1_4 = "RmStartSession" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_KAA_2147910956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.KAA!MTB"
        threat_id = "2147910956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 0a 91 11 00 11 0c 91 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WhiteSnake_AWS_2147925686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnake.AWS!MTB"
        threat_id = "2147925686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnake"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {13 04 09 06 11 04 91 58 20 ff 00 00 00 5f 0d 06 11 04 91 13 0b 06 11 04 06 09 91 9c 06 09 11 0b 9c 06 11 04 91 06 09 91 58 20 ff 00 00 00 5f 13 0c 08 11 0a 02 11 0a 91 06 11 0c 91 61 d2 9c 00 11 0a 17 58}  //weight: 3, accuracy: High
        $x_2_2 = {06 11 07 91 58 07 11 07 91 58 20 ff 00 00 00 5f 0d 06 11 07 91 13 08 06 11 07 06 09 91 9c 06 09 11 08 9c 00 11 07 17 58 13 07 11 07 20 00 01 00 00 fe 04 13 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

