rule Trojan_MSIL_Convagent_ALR_2147832709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.ALR!MTB"
        threat_id = "2147832709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 a2 25 17 28 ?? ?? ?? 0a a2 25 18 72 b3 03 00 70 a2 25 19 28 ?? ?? ?? 0a a2 25 1a 72 07 04 00 70 a2 25 1b 28 ?? ?? ?? 0a a2 25 1c 72 43 04 00 70 a2 25 1d 28 ?? ?? ?? 0a a2 25 1e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_NCS_2147838209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.NCS!MTB"
        threat_id = "2147838209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 03 00 00 04 14 fe 01 0a 06 2c 22 00 72 ?? ?? ?? 70 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 0b 07 80 ?? ?? ?? 04 00 7e ?? ?? ?? 04 0c 2b 00 08 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "xvid.Form1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_NHD_2147838498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.NHD!MTB"
        threat_id = "2147838498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 14 7d 01 00 00 04 02 28 ?? 00 00 0a 00 00 02 28 ?? 00 00 06 00 72 ?? 00 00 70 0a 06 73 ?? 00 00 0a 0b 07 6f ?? 00 00 0a 00 72 ?? 00 00 70 0c 08 07 73 ?? 00 00 0a 0d 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 02 7b ?? 00 00 04 11 04 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Programm.Properties.Resources" ascii //weight: 1
        $x_1_3 = "SELECT name FROM test1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_NCF_2147841371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.NCF!MTB"
        threat_id = "2147841371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 70 00 00 0a 28 ?? ?? 00 0a 2c 07 20 ?? ?? 00 00 10 03 04 06 6f ?? ?? 00 0a 06 6f ?? ?? 00 0a 28 ?? ?? 00 0a 06 6f ?? ?? 00 0a 07 05 6f ?? ?? 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "muclB" ascii //weight: 1
        $x_1_3 = "TocToe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_PSJT_2147844435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.PSJT!MTB"
        threat_id = "2147844435"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 8d 07 00 00 01 13 04 16 13 05 2b 22 08 28 08 00 00 0a 2d 1a 08 28 04 00 00 06 0a 11 04 11 05 06 1f 10 28 09 00 00 0a 9c 11 05 17 58 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_PSRI_2147850747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.PSRI!MTB"
        threat_id = "2147850747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 04 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_1_2 = "gwgalg0k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_SPP_2147852766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.SPP!MTB"
        threat_id = "2147852766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {17 8d 01 00 00 01 13 07 11 07 16 02 a2 11 07 0d 07 14 09 6f ?? ?? ?? 0a 13 04 11 04 14 fe 01 13 06 11 06 38 05 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_PSVQ_2147888535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.PSVQ!MTB"
        threat_id = "2147888535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 31 00 00 04 07 6f ?? 00 00 0a 1f ec 16 73 3d 00 00 06 6f ?? 00 00 06 2b 4f 02 7b 31 00 00 04 07 6f ?? 00 00 0a 1f 14 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_NC_2147891688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.NC!MTB"
        threat_id = "2147891688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 86 00 00 01 25 16 17 9c 25 17 17 9c 25 13 07 17 28 ?? 00 00 0a 26 11 07 16 91 2d 02 2b 20 11 0f 11 06 16 9a 28 ?? 00 00 0a d0 ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 74 ?? 00 00 01 51}  //weight: 5, accuracy: Low
        $x_1_2 = "FirmaElettronicaDDT.frmFIRMA.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_ACV_2147895326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.ACV!MTB"
        threat_id = "2147895326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 16 0b 2b 13 00 07 0a 07 1b fe 01 0c 08 2c 03 00 2b 0e 00 07 17 58 0b 07 1f 0a fe 04 0d 09 2d e4}  //weight: 2, accuracy: High
        $x_1_2 = "visula studio\\bucle\\obj\\Debug\\bucle.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_PTCF_2147896999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.PTCF!MTB"
        threat_id = "2147896999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 04 00 00 04 6f 36 00 00 0a 6f 28 00 00 0a 0a 02 72 f9 00 00 70 06 72 19 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_KAB_2147910962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.KAB!MTB"
        threat_id = "2147910962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 91 04 58 d2 0d 07 08 17 58 91 04 58 d2 13 04 07 08 11 04 9c 07 08 17 58 09 9c 08 18 58 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_SPBF_2147912759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.SPBF!MTB"
        threat_id = "2147912759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0c 2b 29 00 06 08 8f 0c 00 00 01 25 71 0c 00 00 01 72 4b 00 00 70 08 1f 6e 5d 6f ?? 00 00 0a d2 61 d2 81 0c 00 00 01 00 08 17 58 0c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_KAC_2147914905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.KAC!MTB"
        threat_id = "2147914905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YuxzOWxhT7e5RvSI0clvBMy3KPi" wide //weight: 3
        $x_3_2 = {56 00 6f 00 64 00 53 00 6d 00 6f 00 45 00 70 00 70 00 74 00 4e 00 31 00 7a 00 4f 00 63 00 69}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_MX_2147925519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.MX!MTB"
        threat_id = "2147925519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 1f 01 00 70 07 72 cc 01 00 70 28 05 00 00 0a 28 03 00 00 06 00 72 e8 01 00 70 07 72 95 02 00 70 28 05 00 00 0a 28 03 00 00 06 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_AMCU_2147928401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.AMCU!MTB"
        threat_id = "2147928401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 00 07 28 ?? ?? 00 06 26 00 de 0b 07 2c 07 07 6f ?? 00 00 0a 00 dc 28 ?? ?? 00 06 28 ?? ?? 00 06 26 00 de 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_AORA_2147939597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.AORA!MTB"
        threat_id = "2147939597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0b 16 73 ?? 00 00 0a 13 09 20 03 00 00 00 38 ?? ff ff ff 11 0b 11 08 16 1a 6f ?? 00 00 0a 26 20 02 00 00 00 38 ?? ff ff ff 11 08 16 28 ?? 00 00 0a 13 02 20 00 00 00 00 7e ?? 01 00 04 7b ?? 01 00 04 39 ?? ff ff ff 26 20 00 00 00 00 38}  //weight: 5, accuracy: Low
        $x_2_2 = {11 09 11 0c 11 05 11 02 11 05 59 6f ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_NG_2147940552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.NG!MTB"
        threat_id = "2147940552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Beendet sich selbst ohne Benutzerbenachrichtigung" ascii //weight: 1
        $x_1_2 = "Windows Error Reporting deaktivieren" ascii //weight: 1
        $x_1_3 = "Windows Security Notifications deaktivieren" ascii //weight: 1
        $x_1_4 = "DisableWindowsUpdateAccess" ascii //weight: 1
        $x_1_5 = "DisableAntiSpyware" ascii //weight: 1
        $x_2_6 = "WindowStyle Hidden -ExecutionPolicy Bypass -File" ascii //weight: 2
        $x_1_7 = "DisableRealtimeMonitoring $true" ascii //weight: 1
        $x_1_8 = "DisableIOAVProtection $true" ascii //weight: 1
        $x_1_9 = "DisableScriptScanning $true" ascii //weight: 1
        $x_1_10 = "Stop-Service WinDefend -Force" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_AB_2147945022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.AB!MTB"
        threat_id = "2147945022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 20 a0 8e cd e8 58 0d 09 20 b2 4f 09 d2 59 16 16 61 61 16 62 2b b1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_ALIB_2147955685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.ALIB!MTB"
        threat_id = "2147955685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 06 7b ?? 00 00 04 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 02 7b ?? 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 04 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 2b 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Convagent_LMB_2147959453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Convagent.LMB!MTB"
        threat_id = "2147959453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {28 5d 02 00 06 2d 06 16 28 03 01 00 0a 7e 9c 02 00 04 2c 2f 17 80 9a 03 00 04 7e a4 02 00 04 25 2d 17 26 7e a3 02 00 04 fe 06 d6 01 00 06 73 61 00 00 0a 25 80 a4 02 00 04 73 62 00 00 0a 28 65 00 00 0a}  //weight: 20, accuracy: High
        $x_10_2 = {73 f0 01 00 06 80 a0 02 00 04 7e a0 02 00 04 6f e4 01 00 06 2b 2a 7e a0 02 00 04 6f df 01 00 06 2d 0a 7e a0 02 00 04 6f e7 01 00 06 73 04 01 00 0a 20 88 13 00 00 6f 05 01 00 0a 28 6a 00 00 0a 7e a1 02 00 04 2d cf 2a}  //weight: 10, accuracy: High
        $x_5_3 = "OffLineKeyLogger" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

