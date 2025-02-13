rule TrojanSpy_MSIL_AgentTesla_2147727614_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla.gen!bit"
        threat_id = "2147727614"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "amp4Z0wpKzJ5Cg0GDT5sJD0sMw0IDAsaGQ1Afik6NwXr6rrSEQE=" wide //weight: 1
        $x_1_2 = "Sendwebcam" ascii //weight: 1
        $x_1_3 = "%site_username%" wide //weight: 1
        $x_1_4 = "webpanel" wide //weight: 1
        $x_1_5 = "<br>UserName&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:" wide //weight: 1
        $x_1_6 = "<br>VideocardMem&nbsp;&nbsp;:" wide //weight: 1
        $x_1_7 = "<br>IP Address&nbsp;&nbsp;:" wide //weight: 1
        $x_1_8 = "<br><span style=font-style:normal;text-decoration:none;text-transform:none;color:#FF0000;><strong>[clipboard]</strong></span>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_2147729168_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla!bit"
        threat_id = "2147729168"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 20 20 a7 00 00 59 02 7b ?? 00 00 04 61 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 02 16 6f ?? 00 00 0a 20 20 a7 00 00 59 7d ?? 00 00 04 02 17 6f ?? 00 00 0a 06 fe 06 ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {00 00 06 0a 06 7e ?? 00 00 04 16 6f ?? 00 00 0a 20 20 a7 00 00 59 7d ?? 00 00 04 7e ?? 00 00 04 17 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_2147730683_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla"
        threat_id = "2147730683"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fghytutgfnmdfg.My" ascii //weight: 1
        $x_1_2 = "POOYUGHYFUG.My" ascii //weight: 1
        $x_2_3 = "ConfuserEx v1.0.0" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_AgentTesla_2147730683_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla"
        threat_id = "2147730683"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 16 0b 2b 2d 03 25 4b 04 06 1f 0f 5f 95 61 54 04 06 1f 0f 5f 04 06 1f 0f 5f 95 03 25 1a 58 10 01 4b 61 20 84 e2 03 78 58 9e 06 17 58 0a 07 17 58 0b 07 02 37 cf 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_AQ_2147754029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla.AQ!MTB"
        threat_id = "2147754029"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MulticastDelegate" ascii //weight: 1
        $x_1_2 = "StreamWriter" ascii //weight: 1
        $x_1_3 = "TextWriter" ascii //weight: 1
        $x_1_4 = "CreateText" ascii //weight: 1
        $x_1_5 = "WriteLine" ascii //weight: 1
        $x_1_6 = "Flush" ascii //weight: 1
        $x_1_7 = "Combine" ascii //weight: 1
        $x_1_8 = "Stopwatch" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "BitConverter" ascii //weight: 1
        $x_1_11 = "AsyncCallback" ascii //weight: 1
        $x_1_12 = "BinarySearch" ascii //weight: 1
        $x_1_13 = "VideoLAN" ascii //weight: 1
        $x_1_14 = "log.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_RA_2147755782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla.RA!MTB"
        threat_id = "2147755782"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2f 54 68 69 73 20 70 [0-5] 6f 67 72 61 6d 20 71 61 6e 6e 6f 74 20 70 65 20 72 75 6e 20 77 6e 20 44 4f 53 20 7b 6f 64 65}  //weight: 3, accuracy: Low
        $x_3_2 = ".tsxt" ascii //weight: 3
        $x_3_3 = ".rsrq" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_SM_2147755805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla.SM!MTB"
        threat_id = "2147755805"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 11 04 18 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 04 07 6f ?? ?? ?? ?? 28 ?? ?? ?? 0a 6a 61 b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 08 11 05 6f [0-8] 6f ?? 00 00 0a 17 da 33 03 17 2b 01 16 2c ?? 16 0b 07 2c 04 07 17 d6 0b ?? 04 ?? ?? ?? ?? 11 04}  //weight: 10, accuracy: Low
        $x_1_2 = "XOR_Decrypt" ascii //weight: 1
        $x_1_3 = "mIOTA" ascii //weight: 1
        $x_1_4 = "Io.xy" ascii //weight: 1
        $x_1_5 = "DatabaseManager.A.resources" ascii //weight: 1
        $x_1_6 = "DatabaseManager.FrmMenu.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_B_2147832623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla.B!MTB"
        threat_id = "2147832623"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 0f 01 28 ?? 00 00 0a 02 7b ?? 00 00 04 58 12 00 28 ?? 00 00 0a 1a 59 28 ?? 00 00 0a 28 ?? 00 00 0a 38 00 00 00 00 00 02}  //weight: 2, accuracy: Low
        $x_2_2 = "Davis11.Properties.Resources.resources" ascii //weight: 2
        $x_2_3 = "Aeeee" wide //weight: 2
        $x_2_4 = "IsleBotL" wide //weight: 2
        $x_2_5 = "IsleBotR" wide //weight: 2
        $x_2_6 = "IsleTopL" wide //weight: 2
        $x_2_7 = "IsleTopR" wide //weight: 2
        $x_2_8 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 2
        $x_2_9 = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_AA_2147839748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla.AA!MTB"
        threat_id = "2147839748"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 16 13 05 2b 37 11 04 11 05 9a 13 06 09 72 bc 06 00 70 11 06 07 11 06 6f 36 00 00 0a 28 10 00 00 0a 28 37 00 00 0a 72 77 00 00 70 28 14 00 00 0a 28 15 00 00 0a 0d 11 05 17 d6 13 05 11 05 11 04 8e 69 32 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_AgentTesla_NB_2147892222_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/AgentTesla.NB!MTB"
        threat_id = "2147892222"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 72 49 01 00 70 28 ?? ?? ?? 06 7d ?? ?? ?? 04 02 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ForLoopControl" ascii //weight: 1
        $x_1_4 = "gXckg6e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

