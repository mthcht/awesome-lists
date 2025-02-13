rule Trojan_MSIL_Shelm_RDA_2147839817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.RDA!MTB"
        threat_id = "2147839817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "2ea1aa8a-cad3-4620-875e-7f678cc67d2c" ascii //weight: 1
        $x_1_2 = "CreateThreadpoolWait_ShellcodeExecution" ascii //weight: 1
        $x_2_3 = {07 11 07 07 11 07 91 20 ?? ?? ?? ?? 61 d2 9c 11 07 17 58 13 07 11 07 07 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_NSM_2147840171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.NSM!MTB"
        threat_id = "2147840171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 15 00 00 0a 0a 06 8e 2d 22 00 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 0a 02 28 ?? ?? 00 0a 28 ?? ?? 00 0a 14 2a 06 28 ?? ?? 00 2b 73 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Chatgpt-A2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_ASE_2147847988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.ASE!MTB"
        threat_id = "2147847988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 16 2b 15 07 11 16 07 11 16 91 20 dc 00 00 00 61 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_ASE_2147847988_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.ASE!MTB"
        threat_id = "2147847988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 18 00 00 0a 13 05 7e 18 00 00 0a 13 06 11 04 28 ?? ?? ?? 06 12 06 7e 18 00 00 0a 7e 18 00 00 0a 11 05 12 01 18 16 1a 28 ?? ?? ?? 0a 26 06 16 11 06 06 8e 69 28 ?? ?? ?? 0a 7e 18 00 00 0a 13 07 11 04 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_A_2147848526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.A!MTB"
        threat_id = "2147848526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "stream.Write($sendbyte,0,$sendbyte.Length)" wide //weight: 2
        $x_2_2 = "stream.Read($bytes, 0, $bytes.Length))) -ne 0)" wide //weight: 2
        $x_2_3 = "(iex $data 2>&1 | Out-String )" wide //weight: 2
        $x_2_4 = "PS ' + (pwd).Path + '> ')" wide //weight: 2
        $x_2_5 = "(([text.encoding]::ASCII).GetBytes(" wide //weight: 2
        $x_2_6 = "New-Object -TypeName System.Text.ASCIIEncoding).GetString(" wide //weight: 2
        $x_2_7 = "Value (New-Object System.Net.Sockets.TCPClient(" wide //weight: 2
        $x_2_8 = "/c Start-Process $PSHOME\\powershell.exe -ArgumentList" wide //weight: 2
        $x_2_9 = "WindowStyle Hidden" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_ASH_2147850006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.ASH!MTB"
        threat_id = "2147850006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 16 2b 0f 07 11 16 07 11 16 91 d2 9c 11 16 17 58 13 16 11 16 07 8e 69 32 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_KAD_2147894568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.KAD!MTB"
        threat_id = "2147894568"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 11 09 11 11 91 11 0b 28 ?? 00 00 0a 61 d2 9c 11 11 17 58 13 11 11 11 09 8e 69 32 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_KAE_2147898703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.KAE!MTB"
        threat_id = "2147898703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 07 03 8e 69 fe 01 0d 09 2c 02 16 0b 06 08 02 08 8f ?? 00 00 01 25 47 03 07 91 61 d2 25 13 04 52 11 04 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 05 11 05 2d cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_SPNZ_2147902942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.SPNZ!MTB"
        threat_id = "2147902942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 8e 69 0c 7e ?? ?? ?? 0a 20 ?? ?? ?? 00 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? 06 0d 07 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_SPVB_2147903575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.SPVB!MTB"
        threat_id = "2147903575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 d2 9c 11 0d 17 58 13 0d 11 0d 11 0c 8e 69 32 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_HXAA_2147905243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.HXAA!MTB"
        threat_id = "2147905243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 06 04 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 00 08 07 17 73 ?? 00 00 0a 0d 00 09 02 16 02 8e 69 6f ?? 00 00 0a 00 00 de 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_SPPX_2147905416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.SPPX!MTB"
        threat_id = "2147905416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 04 06 28 ?? ?? ?? 0a 73 13 00 00 0a 13 05 11 05 11 04 08 09 6f ?? ?? ?? 0a 16 73 15 00 00 0a 13 06 11 06}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Shelm_SK_2147915520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Shelm.SK!MTB"
        threat_id = "2147915520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 09 11 86 07 11 86 93 28 15 00 00 0a 9c 00 11 86 17 58 13 86 11 86 09 8e 69 fe 04 13 87 11 87 2d de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

