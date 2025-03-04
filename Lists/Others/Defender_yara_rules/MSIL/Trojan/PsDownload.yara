rule Trojan_MSIL_PsDownload_MB_2147825198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.MB!MTB"
        threat_id = "2147825198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-enc UwB0AEEAcgB0AC0AUwBsAE" wide //weight: 1
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
        $x_1_4 = "://24hrstrack.com/loader/" wide //weight: 1
        $x_1_5 = "ComputeBroadcaster" ascii //weight: 1
        $x_1_6 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_MA_2147836631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.MA!MTB"
        threat_id = "2147836631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Powershell -ExecutionPolicy Unrestricted -Command \"Invoke-Webrequest 'http://124.106.197.167" ascii //weight: 1
        $x_1_2 = "Add-MpPreference -ExclusionPath 'C:\\PerfLogs'" ascii //weight: 1
        $x_1_3 = "Bypass -Confirm:$false -Force" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_MA_2147836631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.MA!MTB"
        threat_id = "2147836631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 11 04 07 16 07 8e 69 6f ?? ?? ?? 0a 13 05 09 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 07 2b 00 11 07 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "EE-912RebootReminder.script.ps1" ascii //weight: 1
        $x_1_3 = "WriteResourceToFile" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_MA_2147836631_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.MA!MTB"
        threat_id = "2147836631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "://x.rune-spectrals.com/torrent/uploads/" wide //weight: 5
        $x_2_2 = "Otcsei.Properties" ascii //weight: 2
        $x_2_3 = "Gwrpusjtj" ascii //weight: 2
        $x_2_4 = "836c4ee0-849e-400e-ac77-db85ddce221f" ascii //weight: 2
        $x_1_5 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_GDF_2147839143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.GDF!MTB"
        threat_id = "2147839143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 06 11 04 06 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df}  //weight: 10, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_EAS_2147843926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.EAS!MTB"
        threat_id = "2147843926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 07 16 07 8e 69 28 ?? 00 00 0a 07 0c dd 03 00 00 00 26 de cf}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_PSJQ_2147844711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.PSJQ!MTB"
        threat_id = "2147844711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {38 16 00 00 00 00 06 09 02 03 09 58 91 05 61 d2 9c 00 09 17 58 0d 05 17 58 10 03 09 04 fe 04 13 04 7e 16 00 00 04 38 b6 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_ABRX_2147846495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.ABRX!MTB"
        threat_id = "2147846495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 2d 2b 32 2b 33 72 ?? 00 00 70 7e ?? 00 00 0a 2b 2e 2b 33 1d 2d 0d 26 dd ?? 00 00 00 2b 2f 15 2c f6 2b dc 2b 2b 2b f0 28 ?? 00 00 06 2b cd 28 ?? 00 00 0a 2b cc 07 2b cb 6f ?? 00 00 0a 2b c6 6f ?? 00 00 0a 2b cb 28 ?? 00 00 0a 2b c6 0b 2b ce 0c 2b d2}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_HAA_2147848739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.HAA!MTB"
        threat_id = "2147848739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 2b f5 00 2b 15 72 ?? 00 00 70 2b 15 2b 1a 2b 1f 15 2d 03 26 de 26 2b 1e 2b fa 28 ?? 00 00 0a 2b e4 28 ?? 00 00 06 2b e4 6f ?? 00 00 0a 2b df 28 ?? 00 00 0a 2b da 0a 2b df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_HAB_2147849084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.HAB!MTB"
        threat_id = "2147849084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 00 70 28 ?? 00 00 06 0a dd ?? 00 00 00 26 dd 00 00 00 00 06 2c e6 16 0b 06 8e 69 17 59 0c 38 ?? 00 00 00 06 07 91 0d 06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 0b 08 17 59 0c 07 08 32 e5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_AADZ_2147850150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.AADZ!MTB"
        threat_id = "2147850150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 16 06 7b ?? 0a 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 7e ?? 0a 00 04 25 3a ?? 00 00 00 26 7e ?? 0a 00 04 fe ?? ?? 12 00 06 73 ?? 00 00 0a 25 80 ?? 0a 00 04 28 ?? 00 00 2b 06 fe ?? ?? 12 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "Rqwndbjtikt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_APS_2147889006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.APS!MTB"
        threat_id = "2147889006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 07 17 6f ?? ?? ?? 0a 00 06 07 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 26 00 de 10 06 14 fe 01 0c 08 2d 07 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_AMAB_2147890135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.AMAB!MTB"
        threat_id = "2147890135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 02 7b 03 00 00 04 17 58 20 ff 00 00 00 5f 7d 03 00 00 04 02 02 7b 04 00 00 04 02 7b 02 00 00 04 02 7b 03 00 00 04 91 58 20 ff 00 00 00 5f 7d 04 00 00 04 02 7b 02 00 00 04 02 7b 03 00 00 04 02 7b 04 00 00 04 28 09 00 00 06 03 02 7b 02 00 00 04 02 7b 02 00 00 04 02 7b 03 00 00 04 91 02 7b 02 00 00 04 02 7b 04 00 00 04 91 58 20 ff 00 00 00 5f 91 61 d2 2a}  //weight: 1, accuracy: High
        $x_1_2 = {02 03 91 0a 02 03 02 04 91 9c 02 04 06 9c}  //weight: 1, accuracy: High
        $x_1_3 = "54b9bf24-4458-4529-a6f7-bff7d7b4277d" ascii //weight: 1
        $x_1_4 = "6uD3by7WS6LQiosKT5FlEJ8Dcs4FaEdSw622A0zJWqefdmZQHuTttA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_ENAA_2147902975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.ENAA!MTB"
        threat_id = "2147902975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {26 14 0b 73 ?? 00 00 0a 0c 28 ?? 00 00 06 0b dd ?? 00 00 00 08 39 ?? 00 00 00 08 6f ?? 00 00 0a dc 07 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 2b 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_M_2147903771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.M!MTB"
        threat_id = "2147903771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ether_cmd.pdb" ascii //weight: 1
        $x_1_2 = "c-vkp.ru" wide //weight: 1
        $x_1_3 = "powershell.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PsDownload_MVT_2147907300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PsDownload.MVT!MTB"
        threat_id = "2147907300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PsDownload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1b 28 06 00 00 06 13 0d 73 0c 00 00 0a 13 0e 11 0e 18 8d 18 00 00 01}  //weight: 2, accuracy: High
        $x_1_2 = "whoami" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

