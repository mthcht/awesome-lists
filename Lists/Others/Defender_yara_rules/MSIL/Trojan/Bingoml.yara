rule Trojan_MSIL_Bingoml_FY_2147797664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.FY!MTB"
        threat_id = "2147797664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\nikol\\source\\repos\\Download Manager\\bin\\Debug" ascii //weight: 1
        $x_1_2 = "romspedia" wide //weight: 1
        $x_1_3 = "Download_Manager.Properties.Resources" wide //weight: 1
        $x_1_4 = "Rom Download" wide //weight: 1
        $x_1_5 = "147.182.224.143" wide //weight: 1
        $x_1_6 = "ppidomination_remote" wide //weight: 1
        $x_1_7 = "cOm!KP@$$123f" wide //weight: 1
        $x_1_8 = "SELECT Rom_Name, Rom_Link FROM Rom WHERE Rom_ID = @rom_id" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_RPH_2147830264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.RPH!MTB"
        threat_id = "2147830264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "brainstormvc.me" wide //weight: 1
        $x_1_2 = {2f 00 43 00 73 00 74 00 61 00 72 00 74 00 20 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "devenv" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "Sleep" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_ACS_2147833495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.ACS!MTB"
        threat_id = "2147833495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0b 00 09 17 58 0d 09 20 00 01 00 00 fe 04 13 04 11 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_MA_2147836528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.MA!MTB"
        threat_id = "2147836528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 07 06 6f 20 00 00 0a 69 6f 21 00 00 0a 6f 22 00 00 0a de 28 09 2c 06 09 6f 23 00 00 0a dc}  //weight: 5, accuracy: High
        $x_2_2 = "/C start C:\\Users\\Public\\SysInitVal.exe" wide //weight: 2
        $x_2_3 = "startproc" ascii //weight: 2
        $x_2_4 = "cc648714-e04f-4d83-8a14-ed7e2b627809" ascii //weight: 2
        $x_2_5 = "AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_ABEV_2147837166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.ABEV!MTB"
        threat_id = "2147837166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 1a 28 13 00 00 0a 72 01 00 00 70 28 14 00 00 0a 25 28 03 00 00 06 28 15 00 00 0a 28 16 00 00 0a 26 73 17 00 00 0a 0a}  //weight: 2, accuracy: High
        $x_1_2 = "\\readmercs.txt" wide //weight: 1
        $x_1_3 = "Document.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_NEAA_2147838073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.NEAA!MTB"
        threat_id = "2147838073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7e 04 00 00 04 2d 3d 72 33 00 00 70 0a 06 28 17 00 00 0a 0b 28 18 00 00 0a 07 16 07 8e 69 6f 19 00 00 0a 0a 28 1a 00 00 0a 06 6f 1b 00 00 0a}  //weight: 5, accuracy: High
        $x_2_2 = "Tk1DWENYSkdLSkdLREZLJA==" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_RB_2147838508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.RB!MTB"
        threat_id = "2147838508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pastebin.com/raw/ZpdsPjXV" wide //weight: 1
        $x_1_2 = "Rbx_tool_xmasterp\\Rbx_tool_xmasterp\\obj\\Debug\\Rbx_tool_xmasterp.pdb" ascii //weight: 1
        $x_1_3 = "$90ab7707-9109-47af-9c89-cf89543f04b1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_ABVJ_2147846878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.ABVJ!MTB"
        threat_id = "2147846878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 1f 09 0b 02 0d 16 13 04 2b 28 09 11 04 6f ?? 00 00 0a 0c 06 08 28 ?? 00 00 0a 07 59 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a 0a 11 04 17 58 13 04 11 04 09 6f ?? 00 00 0a 32 ce 06 28 ?? 00 00 0a 0a 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bingoml_NB_2147915400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bingoml.NB!MTB"
        threat_id = "2147915400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bingoml"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "masquerade.blake3" wide //weight: 2
        $x_2_2 = "verify.Properties.Resources" wide //weight: 2
        $x_2_3 = "RSDS/FiQiT" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

