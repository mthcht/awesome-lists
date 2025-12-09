rule Trojan_MSIL_DarkTortilla_NEAA_2147837833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.NEAA!MTB"
        threat_id = "2147837833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0b 07 8e 69 17 d6 8d 43 00 00 01 0a 06 8e 69 17 da 0c 16 0d 2b 0f 06 09 07 16 9a 6f 88 00 00 0a a2 09 17 d6 0d 09 08 31 ed}  //weight: 10, accuracy: High
        $x_10_2 = "https://textbin.net/raw/vwaeuwponp" wide //weight: 10
        $x_2_3 = "AppleWebKit/537.36" wide //weight: 2
        $x_2_4 = "Load" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_A_2147838019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.A!MTB"
        threat_id = "2147838019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0b 16 16 02 17 8d ?? 00 00 01 25 16 11 0b 8c ?? 00 00 01 a2 14 28 ?? 01 00 0a 28 ?? 01 00 0a 16 16 11 0e 11 0d 18 28 ?? 01 00 06 18 28 ?? 01 00 06 b4 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MBW_2147838301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MBW!MTB"
        threat_id = "2147838301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 03 8c ?? 00 00 01 a2 25 0b 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0c 28 ?? 00 00 0a 0d 19 13 05 2b 8a}  //weight: 1, accuracy: Low
        $x_1_2 = "Cn4d0N.Resources.resource" ascii //weight: 1
        $x_1_3 = "44e6ab2979bf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_B_2147838564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.B!MTB"
        threat_id = "2147838564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 03 5d 0c}  //weight: 2, accuracy: High
        $x_2_2 = {04 05 60 04 66 05 66 60 5f 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ATO_2147838636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ATO!MTB"
        threat_id = "2147838636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 25 2d 55 25 2d f3 13 04 2b 1c 11 08 11 04 11 0a 11 04 11 0a 8e 69 5d 91 9e 11 09 11 04 11 04 9e 11 04 17 58 13 04 11 04 20 00 01 00 00 32 db}  //weight: 1, accuracy: High
        $x_1_2 = {11 09 09 94 13 07 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 07 9e 16 3a ?? ?? ?? ff 11 09 11 09 09 94 11 09 11 05 94 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_D_2147839113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.D!MTB"
        threat_id = "2147839113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AppLaunch.exe" wide //weight: 2
        $x_2_2 = "svchost.exe" wide //weight: 2
        $x_2_3 = "RegAsm.exe" wide //weight: 2
        $x_2_4 = "InstallUtil.exe" wide //weight: 2
        $x_2_5 = "mscorsvw.exe" wide //weight: 2
        $x_2_6 = "AddInProcess32.exe" wide //weight: 2
        $x_2_7 = "msbuild.exe" wide //weight: 2
        $x_2_8 = "vmware usb pointing device" wide //weight: 2
        $x_2_9 = "WScript.Shell" wide //weight: 2
        $x_2_10 = "tpvcgateway" wide //weight: 2
        $x_2_11 = "FakeMessage" ascii //weight: 2
        $x_2_12 = "AddonPackage" ascii //weight: 2
        $x_2_13 = "InstallStruct" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_C_2147839190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.C!MTB"
        threat_id = "2147839190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 08 17 8d ?? 00 00 01 25 16 09 28 ?? 00 00 0a 9d 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a b4 9c 11 07 17 d6 13 07 11 07 11 06 31 d5}  //weight: 2, accuracy: High
        $x_1_3 = "HttpWebRequest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_E_2147840498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.E!MTB"
        threat_id = "2147840498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 05 60 04 66 05 66 60 5f}  //weight: 2, accuracy: High
        $x_2_2 = {02 03 5d 0c 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_F_2147841905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.F!MTB"
        threat_id = "2147841905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 05 60 04 66 05 66 60 5f}  //weight: 2, accuracy: High
        $x_2_2 = {02 03 5d 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_G_2147842675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.G!MTB"
        threat_id = "2147842675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 11 05 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 16 16 11 09 11 08 18 28 ?? 02 00 06 28 ?? 00 00 0a 18 28 ?? 02 00 06 28 ?? 00 00 0a 8c ?? 00 00 01 a2 14 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_H_2147843174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.H!MTB"
        threat_id = "2147843174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 20 00 e1 f5 05 5a 7e ?? 00 00 04 6f ?? 00 00 06 17 58 20 00 e1 f5 05 5a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ADT_2147843434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ADT!MTB"
        threat_id = "2147843434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 16 fe 01 13 04 11 04 2c 22 08 18 9a 74 74 00 00 01 20 3b 6b 20 00 08 16 9a 74 74 00 00 01 16 20 00 ee 02 00 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MBCO_2147843618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MBCO!MTB"
        threat_id = "2147843618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 2c 5f 07 07 72 67 0a 00 70 6f ?? 00 00 0a 17 d6 73 ?? 00 00 0a 17 1f 09 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 72 6b 0a 00 70 6f ?? 00 00 0a 13 04 11 04 2c 2b 28 ?? 00 00 06 13 05 11 05 16 fe 01 13 06 11 06 2c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_I_2147845489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.I!MTB"
        threat_id = "2147845489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 2b d8 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 06 74 ?? 00 00 1b 17 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_PSMF_2147846244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.PSMF!MTB"
        threat_id = "2147846244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d0 57 00 00 06 26 18 13 08 2b d6 28 ?? ?? ?? 06 0b 28 ?? ?? ?? 0a 07 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 17 28 ?? ?? ?? 06 75 ?? ?? ?? 1b 0c 16 13 08 2b a5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_PSNP_2147846656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.PSNP!MTB"
        threat_id = "2147846656"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 2b f9 28 50 01 00 06 28 ?? ?? ?? 0a 0c 06 75 02 00 00 1b 16 9a 28 ?? ?? ?? 0a 06 75 02 00 00 1b 17 9a 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RDA_2147846711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RDA!MTB"
        threat_id = "2147846711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1f6aa4d0-34ed-47f0-8fda-9f866cc5153a" ascii //weight: 1
        $x_1_2 = "Lf24" ascii //weight: 1
        $x_1_3 = "y7Z2N" ascii //weight: 1
        $x_1_4 = "Cj75W" ascii //weight: 1
        $x_1_5 = "s2Q0H" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPX_2147847279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPX!MTB"
        threat_id = "2147847279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 0a 75 0c 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 0c 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1}  //weight: 1, accuracy: High
        $x_1_2 = "get_WhiteSmoke" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "NewLateBinding" ascii //weight: 1
        $x_1_7 = "get_DarkSeaGreen" ascii //weight: 1
        $x_1_8 = "Activator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_K_2147847337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.K!MTB"
        threat_id = "2147847337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 6a 23}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a b9 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 18 13 07 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_J_2147847406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.J!MTB"
        threat_id = "2147847406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 a2 14 28 ?? 00 00 0a 23 00 00 00 00 00 00 1a 40 28 ?? 00 00 0a 8c ?? 00 00 01 28 ?? 00 00 0a a2 14 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_L_2147848451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.L!MTB"
        threat_id = "2147848451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 a2 25 17 11 04 6a 23 0b 00 18 8d ?? 00 00 01 25 16 07 8c}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 a2 14 28 14 00 40 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a b9 61 8c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AABP_2147849069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AABP!MTB"
        threat_id = "2147849069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 1d 5d 16 fe 01 0d 09 2c 40 02 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 10 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 07 17 d6 0b 07 08 fe 04 13 05 11 05 2d a8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AABQ_2147849071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AABQ!MTB"
        threat_id = "2147849071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 1a 5d 16 fe 01 0d 09 2c 56 03 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 03 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 6a 1f 40 6a 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 07 17 d6 0b 07 08 fe 04 13 05 11 05 2d 92}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AABL_2147849181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AABL!MTB"
        threat_id = "2147849181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 1d 5d 16 fe 01 0d 09 2c 42 02 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 10 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 00 00 00 07 17 d6 0b 00 07 08 fe 04 13 05 11 05 2d a4}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AACG_2147849336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AACG!MTB"
        threat_id = "2147849336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 1a 5d 16 fe 01 0d 09 2c 56 03 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 03 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 6a 1f 40 6a 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 07 17 d6 0b 07 08 fe 04 13 05 11 05 2d 92 03 74 ?? 00 00 1b 0a 06 75 ?? 00 00 1b 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AADH_2147849746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AADH!MTB"
        threat_id = "2147849746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 1a 5d 16 fe 01 2c 56 02 17 8d ?? 00 00 01 25 16 06 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 02 18 8d ?? 00 00 01 25 16 06 8c ?? 00 00 01 a2 25 17 08 6a}  //weight: 2, accuracy: Low
        $x_2_2 = {0a b9 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 06 17 d6 0a 06 07 fe 04 2d 98}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AADT_2147850025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AADT!MTB"
        threat_id = "2147850025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1e 13 07 38 ?? fe ff ff 1c 13 07 38 ?? fe ff ff 07 17 d6 0b 17 13 07 38 ?? fe ff ff 07 08 fe 04 13 05 11 05 2d 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAEJ_2147850270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAEJ!MTB"
        threat_id = "2147850270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 18 5d 16 fe 01 0d 09 2c 42 02 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 01 00 0a 28 ?? 00 00 0a 13 04 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 01 00 0a 00 00 00 07 17 d6 0b 00 07 08 fe 04 13 05 11 05 2d a4}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAEB_2147850701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAEB!MTB"
        threat_id = "2147850701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 28 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 17 13 07 38 ?? fe ff ff 1a 13 07 38 ?? fe ff ff 07 17 d6 0b 1f 0a 13 07 38 ?? fe ff ff 07 08 fe 04 13 05 11 05 2d 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAEX_2147850714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAEX!MTB"
        threat_id = "2147850714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 1f 0b 13 07 38 ?? ff ff ff 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 48 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1a 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAFJ_2147850724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAFJ!MTB"
        threat_id = "2147850724"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 1e 13 07 38 ?? ff ff ff 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 48 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1a 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAFM_2147850726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAFM!MTB"
        threat_id = "2147850726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 1f 0b 13 07 38 ?? ff ff ff 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 48 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 11 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAFR_2147850990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAFR!MTB"
        threat_id = "2147850990"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 16 13 07 38 ?? ff ff ff 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 48 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1f 0b 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAFV_2147851002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAFV!MTB"
        threat_id = "2147851002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 08 1a 5d 16 fe 01 13 05 11 05 2c 1d 07 11 04 1f 29 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 10 00 07 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 09 6f ?? 00 00 0a 13 06 11 06 2d a9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAFW_2147851015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAFW!MTB"
        threat_id = "2147851015"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 08 19 5d 16 fe 01 13 05 11 05 2c 1d 07 11 04 1f 26 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 10 00 07 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 09 6f ?? 00 00 0a 13 06 11 06 2d a9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RDB_2147851018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RDB!MTB"
        threat_id = "2147851018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "58670a9a-be07-4963-b4a6-9ab04459d68f" ascii //weight: 1
        $x_1_2 = "r8NHb47Ctm0Q9Fey5WTo2a3Y6Zip1" ascii //weight: 1
        $x_1_3 = "d9S1Xk" ascii //weight: 1
        $x_1_4 = "n2P6Tg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAGE_2147851128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAGE!MTB"
        threat_id = "2147851128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 04 1f 1a 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 17 13 0a 38 ?? ff ff ff 00 07 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 17 13 0a 38 ?? ff ff ff 08 17 d6 0c 00 1d 13 0a 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAGF_2147851132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAGF!MTB"
        threat_id = "2147851132"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 0b 16 0c 2b 30 02 08 91 0d 08 18 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 28 ?? 00 00 06 9c 08 04 fe 01 13 06 11 06 2c 07 28 ?? 00 00 0a 0a 00 00 08 17 d6 0c 08 07 31 cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAGK_2147851223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAGK!MTB"
        threat_id = "2147851223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 04 1f 1a 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 1a 13 0a 38 ?? ff ff ff 00 07 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 1a 13 0a 38 ?? ff ff ff 08 17 d6 0c 00 1d 13 0a 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAGM_2147851307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAGM!MTB"
        threat_id = "2147851307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 14 20 ca 00 00 00 20 9a 00 00 00 28 ?? 00 00 2b 1f 1d 1f 0b 28 ?? 00 00 2b 13 04 1f 09 13 07 38 ?? fe ff ff 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 28 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 18 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAGP_2147851403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAGP!MTB"
        threat_id = "2147851403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 19 5d 16 fe 01 0d 09 2c 56 02 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 6a 1f 14 6a 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 07 17 d6 0b 07 08 fe 04 13 05 11 05 2d 92}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAIB_2147851979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAIB!MTB"
        threat_id = "2147851979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 18 13 07 38 ?? fe ff ff 1f 09 13 07 38 ?? fe ff ff 07 17 d6 0b 16 13 07 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAIC_2147851986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAIC!MTB"
        threat_id = "2147851986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1e 13 07 38 ?? fe ff ff 1f 0b 13 07 38 ?? fe ff ff 07 17 d6 0b 1c 13 07 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAIE_2147851992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAIE!MTB"
        threat_id = "2147851992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1f 0b 13 07 38 ?? fe ff ff 1d 13 07 38 ?? fe ff ff 07 17 d6 0b 1a 13 07 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAIJ_2147852091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAIJ!MTB"
        threat_id = "2147852091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {17 da 0c 2b 47 07 19 5d 16 fe 01 13 04 11 04 2c 0b 02 07 02 07 91 1f 1a 61 b4 9c 00 00 02 07 91 0d 08 19 5d 16 fe 01 13 05 11 05 2c 0b 02 08 02 08 91 1f 1a 61 b4 9c 00 00 02 07 02 08 91 9c 02 08 09 9c 07 17 d6 0b 08 17 da 0c 00 07 08 fe 04 13 06 11 06 2d af}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAIK_2147852096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAIK!MTB"
        threat_id = "2147852096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b 13 09 2b c4 09 74 ?? 00 00 01 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 07 74 ?? 00 00 1b 11 04 1f 09 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 19 13 09 2b 8f 08 17 d6 0c 1b 13 09 2b 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAIR_2147852243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAIR!MTB"
        threat_id = "2147852243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 07 11 07 28 ?? 00 00 0a 03 28 ?? ?? 00 06 0d 16 13 0c 2b 9d 07 75 ?? 00 00 1b 11 07 1f 0a 8c ?? 00 00 01 28 ?? 01 00 0a 28 ?? 01 00 0a 6f ?? 01 00 0a 08 17 d6 0c 1a 13 0c 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAIU_2147852339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAIU!MTB"
        threat_id = "2147852339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 06 16 13 0c 2b c3 11 06 74 ?? 00 00 01 6f ?? 00 00 0a 28 ?? 00 00 0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 19 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 16 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAJF_2147852563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAJF!MTB"
        threat_id = "2147852563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 06 1e 13 0c 2b c3 11 06 74 ?? 00 00 01 6f ?? 00 00 0a 28 ?? 00 00 0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1a 13 0c 2b 9d 07 74 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 1e 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAJG_2147852576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAJG!MTB"
        threat_id = "2147852576"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 12 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1d 13 07 38 ?? fe ff ff 1c 13 07 38 ?? fe ff ff 07 17 d6 0b 1e 13 07 38 ?? fe ff ff 07 08 fe 04 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAJH_2147852589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAJH!MTB"
        threat_id = "2147852589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 1c 13 07 38 ?? ff ff ff 02 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1f 28 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 18}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAJL_2147852653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAJL!MTB"
        threat_id = "2147852653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {05 0c 16 0d 2b 38 03 09 91 13 04 09 1d 5d 13 05 07 11 05 9a 13 06 03 09 02 11 06 11 04 28 ?? 00 00 06 9c 09 05 fe 01 13 07 11 07 2c 0c 7e ?? 00 00 04 28 ?? ?? 00 06 0a 00 00 09 17 d6 0d 09 08 31 c4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAJS_2147852770_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAJS!MTB"
        threat_id = "2147852770"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 07 74 ?? 00 00 1b 11 04 1f 09 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 1a 13 09 2b 8f 08 17 d6 0c 1d 13 09 2b 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_M_2147852833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.M!MTB"
        threat_id = "2147852833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 25 16 28 ?? ?? 00 06 a2 14 14 14 28}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 25 17 28 ?? 00 00 2b a2 14 14 14 17 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAJX_2147852851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAJX!MTB"
        threat_id = "2147852851"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1b 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 17 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAJZ_2147852864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAJZ!MTB"
        threat_id = "2147852864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1e 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 17 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKE_2147852970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKE!MTB"
        threat_id = "2147852970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 18 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 1d 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKF_2147852980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKF!MTB"
        threat_id = "2147852980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1e 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 1c 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKG_2147852981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKG!MTB"
        threat_id = "2147852981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 19 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 1c 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_N_2147853008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.N!MTB"
        threat_id = "2147853008"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 14 14 1c 20 ?? ?? ?? 5a 28 ?? 00 00 06 18 8d ?? 00 00 01 25 17 28 ?? 00 00 2b a2 14 14 14 17 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKK_2147853020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKK!MTB"
        threat_id = "2147853020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1b 13 0c 2b 9d 07 74 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 1a 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKL_2147853021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKL!MTB"
        threat_id = "2147853021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1b 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 16 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKO_2147853039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKO!MTB"
        threat_id = "2147853039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 07 09 b4 6f ?? 00 00 0a 00 08 17 d6 0c 00 11 06 6f ?? 00 00 0a 13 08 11 08 2d c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKP_2147853043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKP!MTB"
        threat_id = "2147853043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 19 13 0c 2b 9d 07 74 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 17 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKV_2147853235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKV!MTB"
        threat_id = "2147853235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 19 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 17 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAKX_2147853243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAKX!MTB"
        threat_id = "2147853243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1e 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c ?? 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AALB_2147887416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AALB!MTB"
        threat_id = "2147887416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 74 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1d 13 0c 2b 92 08 17 d6 0c 1b 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AALD_2147887432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AALD!MTB"
        threat_id = "2147887432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 18 13 0c 2b 9d 07 74 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 17 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AALG_2147888151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AALG!MTB"
        threat_id = "2147888151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 13 18 8d ?? 00 00 01 25 16 11 1d 8c ?? 00 00 01 a2 25 17 28 ?? 01 00 06 11 1d 18 d6 5d 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 11 1d 17 d6 13 1d 11 1d 1f 0a 31 ca}  //weight: 5, accuracy: Low
        $x_1_2 = "qqazsggfgfdddggddgsdw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AALK_2147888203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AALK!MTB"
        threat_id = "2147888203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 74 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1b 13 0c 2b 92 08 17 d6 0c 1c 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AALL_2147888216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AALL!MTB"
        threat_id = "2147888216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 74 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 19 13 0c 2b 92 08 17 d6 0c 1e 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AALP_2147888229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AALP!MTB"
        threat_id = "2147888229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1a 13 0c 38 ?? ff ff ff 08 17 d6 0c 1c 13 0c 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AALQ_2147888270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AALQ!MTB"
        threat_id = "2147888270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1e 13 0c 2b 92 08 17 d6 0c ?? 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MBHT_2147888484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MBHT!MTB"
        threat_id = "2147888484"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 09 91 13 04 09 1d 5d 13 05 07 11 05 9a 13 06 03 09 02 11 06 11 04 28 ?? 00 00 06 9c 09 05 fe 01 13 07 11 07 2c 07 28 ?? 00 00 0a 0a 00 00 09 17 d6 0d 09 08 31 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 73 00 00 0d 49 00 6e 00 76 00 6f 00 6b 00 65 00 00 09 4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAMV_2147888927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAMV!MTB"
        threat_id = "2147888927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 07 11 04 1c 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 19 13 09 2b 98 00 08 17 d6 0c 00 ?? 13 09 2b 8d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAMW_2147888928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAMW!MTB"
        threat_id = "2147888928"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 17 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 16 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AANN_2147889126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AANN!MTB"
        threat_id = "2147889126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1c 13 0c 2b 9d 07 74 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c 1d 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AANP_2147889305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AANP!MTB"
        threat_id = "2147889305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 74 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? ?? 00 06 b4 6f ?? ?? 00 0a 1d 13 0c 2b 92 08 17 d6 0c 19 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AANW_2147889428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AANW!MTB"
        threat_id = "2147889428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1b 13 0c 2b 92 08 17 d6 0c ?? 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AANX_2147889482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AANX!MTB"
        threat_id = "2147889482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 19 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c ?? 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAOG_2147890072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAOG!MTB"
        threat_id = "2147890072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 74 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1e 13 0c 2b 92 08 17 d6 0c ?? 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAOI_2147890074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAOI!MTB"
        threat_id = "2147890074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 16 13 0c 2b 92 08 17 d6 0c ?? 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAOM_2147890078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAOM!MTB"
        threat_id = "2147890078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 0d 1a 13 0c 2b 9d 07 75 ?? 00 00 1b 09 b4 6f ?? 00 00 0a 08 17 d6 0c ?? 13 0c 2b 87}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAOP_2147890286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAOP!MTB"
        threat_id = "2147890286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 07 11 04 1d 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 18 13 09 2b 98 00 08 17 d6 0c 00 19 13 09 2b 8d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAOQ_2147890287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAOQ!MTB"
        threat_id = "2147890287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 07 17 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 11 06 a2 14 28 ?? 00 00 0a 1e 8c ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 27}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAQB_2147891682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAQB!MTB"
        threat_id = "2147891682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 00 08 17 d6 0c 00 11 06 6f ?? 00 00 0a 13 08 11 08 2d cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MKV_2147891801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MKV!MTB"
        threat_id = "2147891801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0c 07 0d 16 13 04 2b 1a 08 03 11 04 9a 28 b4 00 00 0a 1f 5d da b4 6f b5 00 00 0a 00 11 04 17 d6 13 04 11 04 09 31 e1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAQF_2147891805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAQF!MTB"
        threat_id = "2147891805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1c 13 0c 2b 92 08 17 d6 0c ?? 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_KA_2147892120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.KA!MTB"
        threat_id = "2147892120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 06 1f 64 da 13 06 00 11 06 1f 64 fe 02 13 09 11 09 2d ec}  //weight: 10, accuracy: High
        $x_1_2 = "Mvekfmlsfllsdvl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AARF_2147892364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AARF!MTB"
        threat_id = "2147892364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 75 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? ?? 00 06 b4 6f ?? 00 00 0a 16 13 0c 2b 85 08 17 d6 0c 1d 13 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AARU_2147892564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AARU!MTB"
        threat_id = "2147892564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 06 07 75 ?? 00 00 1b 11 06 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 16 13 0b 2b 92 08 17 d6 0c ?? 13 0b 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AASF_2147892861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AASF!MTB"
        threat_id = "2147892861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 8e 69 8d ?? 00 00 01 0c 16 0d 2b 0d 08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AASM_2147892971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AASM!MTB"
        threat_id = "2147892971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 74 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? 00 00 06 b4 6f ?? 00 00 0a 1a 13 0a 2b 92 08 17 d6 0c 19 13 0a 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MBJZ_2147893071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MBJZ!MTB"
        threat_id = "2147893071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d2a8f04e-ec92-4b6f-a086-be4950fa7ef7" ascii //weight: 1
        $x_1_2 = "Fb2q1L8WmPg0n9B5NeJy74Qsr6A3CxYp21S" ascii //weight: 1
        $x_1_3 = "5fe7273536bd1b.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AASU_2147893086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AASU!MTB"
        threat_id = "2147893086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 74 ?? 00 00 1b 11 07 28 ?? 00 00 0a 03 28 ?? ?? 00 06 b4 6f ?? ?? 00 0a 1e 13 0c 2b 92 08 17 d6 0c 1c 13 0c 2b 89}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_O_2147893850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.O!MTB"
        threat_id = "2147893850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 61 0b 07 0a 06 2a}  //weight: 10, accuracy: High
        $x_5_2 = {00 00 01 25 16 16 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 14 14}  //weight: 5, accuracy: Low
        $x_5_3 = {00 00 01 25 17 16 8d ?? 00 00 01 a2 14 14 14 17 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkTortilla_AAUG_2147894291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAUG!MTB"
        threat_id = "2147894291"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 11 04 74 ?? 00 00 1b 6f ?? 01 00 0a 1a 13 0c 2b b3 11 05 74 ?? 00 00 01 11 05 74 ?? 00 00 01 6f ?? 01 00 0a 11 05 75 ?? 00 00 01 6f ?? 01 00 0a 6f ?? 01 00 0a 13 06 1c 13 0c 2b 88}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ABGA_2147896496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ABGA!MTB"
        threat_id = "2147896496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 15 18 d6 5d 6f ?? ?? ?? 0a 11 15 17 d6 13 15 11 15 1f 0a 31 de 22 00 11 13 74 ?? ?? ?? 1b 28}  //weight: 1, accuracy: Low
        $x_1_2 = "44S4y4s44t44e44m4" wide //weight: 1
        $x_1_3 = "44R444e44f444444l44e4cti44o4n" wide //weight: 1
        $x_1_4 = "444A4s444s4e44m4bl444y444" wide //weight: 1
        $x_1_5 = "vcn su89" wide //weight: 1
        $x_1_6 = "[QWEPOUMNX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAWR_2147896797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAWR!MTB"
        threat_id = "2147896797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 0b 16 0c 2b 1e 02 08 91 0d 08 1d 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 28 ?? 00 00 06 9c 08 17 d6 0c 08 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAWS_2147896808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAWS!MTB"
        threat_id = "2147896808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 1b 13 0a 2b a8 09 74 ?? 00 00 01 09 75 ?? 00 00 01 6f ?? 00 00 0a 09 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 18 13 0a 2b 80}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 16 02 8e 69 6f ?? 00 00 0a 18 13 0e 2b c1 11 06 75 ?? 00 00 01 6f ?? 00 00 0a de 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAXD_2147897144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAXD!MTB"
        threat_id = "2147897144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 19 13 0a 2b a8 09 75 ?? 00 00 01 09 74 ?? 00 00 01 6f ?? 00 00 0a 09 74 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 1b 13 0a 2b 80}  //weight: 2, accuracy: Low
        $x_2_2 = {11 06 75 61 00 00 01 02 28 ?? 00 00 2b 28 ?? 00 00 2b 16 02 8e 69 6f ?? 00 00 0a 18 13 0e 2b c1 11 06 75 ?? 00 00 01 6f ?? 00 00 0a de 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAXK_2147897417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAXK!MTB"
        threat_id = "2147897417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 13 0b 2b a8 09 75 ?? 00 00 01 09 74 ?? 00 00 01 6f ?? 00 00 0a 09 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 1b 13 0b 2b 80}  //weight: 2, accuracy: Low
        $x_2_2 = {11 07 74 78 00 00 01 02 28 ?? 00 00 2b 28 ?? 00 00 2b 16 02 8e 69 6f ?? 00 00 0a 18 13 0f 2b c1 11 07 75 ?? 00 00 01 6f ?? 00 00 0a de 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAXL_2147897426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAXL!MTB"
        threat_id = "2147897426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 08 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 00 73 ?? 00 00 0a 13 05 00 11 05 11 04 17 73 ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 00 de 0e 00 11 07 2c 08 11 07 6f ?? 00 00 0a 00 dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAXQ_2147897537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAXQ!MTB"
        threat_id = "2147897537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 08 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 00 73 ?? 00 00 0a 13 05 00 11 05 11 04 17 73 ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 00 de 0e}  //weight: 4, accuracy: Low
        $x_1_2 = "L.o.a.d." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAYH_2147898108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAYH!MTB"
        threat_id = "2147898108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 05 74 ?? 00 00 01 11 04 75 ?? 00 00 1b 6f ?? 00 00 0a 16 13 0c 2b b3 11 05 75 ?? 00 00 01 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {01 02 16 02 8e 69 6f ?? 00 00 0a 11 08 74 ?? 00 00 01 6f ?? 00 00 0a 19 13 10 2b bf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAZC_2147898701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAZC!MTB"
        threat_id = "2147898701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 1f 0c 13 09 38 ?? ff ff ff 07 74 ?? 00 00 1b 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 11 04 12 05 28 ?? 00 00 0a 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AAZL_2147898796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AAZL!MTB"
        threat_id = "2147898796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 05 74 ?? 00 00 01 11 04 74 ?? 00 00 1b 6f ?? 00 00 0a 1a 13 0c 2b b3 11 05 74 ?? 00 00 01 11 05 74 ?? 00 00 01 6f ?? 00 00 0a 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {01 02 16 02 8e 69 6f ?? 00 00 0a 11 08 75 ?? 00 00 01 6f ?? 00 00 0a 1b 13 10 2b bf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RDC_2147901100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RDC!MTB"
        threat_id = "2147901100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 6f a6 00 00 0a 13 05 17 13 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_CFAA_2147901487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.CFAA!MTB"
        threat_id = "2147901487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 11 05 11 04 12 05 28 ?? 00 00 0a 13 07 1c 13 09 21 00 07 75 ?? 00 00 1b 08 28 ?? 00 00 0a 6f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_P_2147901495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.P!MTB"
        threat_id = "2147901495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 09 a2 25 13 0b 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 0c 28 ?? 00 00 0a 11 0c ?? ?? 00 00 1b 16 91}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_CKAA_2147901565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.CKAA!MTB"
        threat_id = "2147901565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 14 72 41 0c 00 70 18 8d ?? 00 00 01 25 16 09 25 13 05 14 72 33 0c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a a2 25 17 09 25 13 06 14 72 3b 0c 00 70 16 8d ?? 00 00 01 14 14 14}  //weight: 3, accuracy: Low
        $x_2_2 = "L o a d" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_CSAA_2147901943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.CSAA!MTB"
        threat_id = "2147901943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 02 14 72 e8 14 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 18 13 13 2b af 11 09 75 ?? 00 00 01 6f ?? 00 00 0a 11 08 75 ?? 00 00 01 6f ?? 00 00 0a 0d de 49}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_DDAA_2147902134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.DDAA!MTB"
        threat_id = "2147902134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 72 7e 35 00 70 17 8d ?? 00 00 01 25 16 d0 ?? 00 00 1b 28 ?? 00 00 0a a2 6f ?? 00 00 0a 0c 08 14 17 8d ?? 00 00 01 25 16 02 a2 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 09 0a de 12}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_DFAA_2147902210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.DFAA!MTB"
        threat_id = "2147902210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 3b 0b 00 70 17 8d ?? 00 00 01 25 16 02 a2 25 0c 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0d 28 ?? 00 00 0a 09 74 ?? 00 00 1b 16 91 2d 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_DKAA_2147902302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.DKAA!MTB"
        threat_id = "2147902302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 11 04 75 ?? 00 00 01 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 13 05 1c 13 12 2b 8d 11 05 75 ?? 00 00 01 6f ?? 01 00 0a 13 06 02 73 ?? 01 00 0a 13 07 11 07 75 ?? 00 00 01 11 06 74 ?? 00 00 01 16 73 ?? 01 00 0a 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MMK_2147902327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MMK!MTB"
        threat_id = "2147902327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0a 2b 89 09 75 aa 00 00 01 19 6f ?? ?? ?? 0a 09 75 aa 00 00 01 07 75 09 00 00 1b 6f 48 01 00 0a 18 13 0a 38 64 ff ff ff 09 75 aa 00 00 01 07 74 09 00 00 1b 6f 49 01 00 0a 09 75 aa 00 00 01 09 74 aa 00 00 01 6f 4a 01 00 0a 09 75 aa 00 00 01 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 1a 13 0a 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_DNAA_2147902398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.DNAA!MTB"
        threat_id = "2147902398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 09 11 08 16 91 2d 02 2b 1f 11 06 14 72 ?? ?? 00 70 17 8d ?? 00 00 01 25 16 11 07 16 9a a2 14 14 17 17 28 ?? 00 00 0a 00 11 09 28 ?? 00 00 0a a2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_DOAA_2147902406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.DOAA!MTB"
        threat_id = "2147902406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 18 13 13 2b af}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_DRAA_2147902478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.DRAA!MTB"
        threat_id = "2147902478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 03 28 ?? 00 00 0a 28 ?? 00 00 0a d6 13 05 04 50 06 17 8d ?? 00 00 01 25 16 11 05 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 17 d6 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ECAA_2147902771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ECAA!MTB"
        threat_id = "2147902771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 16 1e 28 ?? 00 00 0a 7e ?? 00 00 04 2c 07 7e ?? 00 00 04 2b 16 7e ?? 00 00 04 fe ?? ?? 01 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_FMAA_2147903371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.FMAA!MTB"
        threat_id = "2147903371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 1b 13 0c 2b b4 11 04 75 ?? 00 00 01 17 6f ?? 00 00 0a 11 04 74 ?? 00 00 01 18 6f ?? 00 00 0a 18 13 0c 2b 95 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 13 05}  //weight: 2, accuracy: Low
        $x_2_2 = {02 16 02 8e 69 6f ?? 00 00 0a de 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_GEAA_2147903899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.GEAA!MTB"
        threat_id = "2147903899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 11 04 18 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 05 00 73 ?? 00 00 0a 13 06 00 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 00 de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_GPAA_2147904298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.GPAA!MTB"
        threat_id = "2147904298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 00 73 ?? 00 00 0a 13 05 00 11 05 11 04 17 73 ?? 00 00 0a 13 06 11 06 02 16 02 8e 69 6f ?? 00 00 0a 00 de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_GSAA_2147904399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.GSAA!MTB"
        threat_id = "2147904399"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff 11 04 75 ?? 00 00 1b 11 05 28 ?? 01 00 0a 6f ?? 01 00 0a 11 0c 11 0b 12 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ND_2147904606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ND!MTB"
        threat_id = "2147904606"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 74 0b 00 00 1b 28 ?? ?? ?? 06 14 14 14 1a 20 ?? ?? ?? 64 28 54 02 00 06 16 8d ?? ?? ?? 01 14 14 14 28 ?? ?? ?? 0a 74 0b 00 00 1b}  //weight: 5, accuracy: Low
        $x_1_2 = "Ed3w1.HKs.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_HHAA_2147904846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.HHAA!MTB"
        threat_id = "2147904846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b 0d 11 08 28 ?? ?? 00 0a 13 05 11 05 16 fe 02 13 09 11 09 2c 0d 11 04 09 16 11 05 6f ?? 00 00 0a 00 00 00 00 11 05 16 fe 02 13 0a 11 0a 3a ?? ff ff ff 07 11 04 6f ?? 00 00 0a 6f ?? ?? 00 0a 00 de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_IBAA_2147905341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.IBAA!MTB"
        threat_id = "2147905341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 06 1e 5d 16 fe 01 13 07 11 07 2c 0c 02 11 06 02 11 06 91 1f 5d 61 b4 9c 11 06 17 d6 13 06 11 06 11 05 31 db}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_IEAA_2147905444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.IEAA!MTB"
        threat_id = "2147905444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 1d 5d 16 fe 01 0d 09 2c 0a 02 08 02 08 91 1f 34 61 b4 9c 08 17 d6 0c 08 07 31 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_IHAA_2147905596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.IHAA!MTB"
        threat_id = "2147905596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 09 07 6f ?? 00 00 0a 00 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 00 11 05 13 06 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 17 73 ?? 00 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 0c de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_KIAA_2147907482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.KIAA!MTB"
        threat_id = "2147907482"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 8e 69 17 da 0a 16 0b 2b 16 07 1d 5d 16 fe 01 0c 08 2c 08 02 07 02 07 91 03 61 9c 07 17 d6 0b 07 06 31 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RDD_2147907710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RDD!MTB"
        threat_id = "2147907710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 28 a3 00 00 06 0d 09 28 a4 00 00 06 13 04 11 04 08 6f b6 00 00 0a 00 08 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_KZAA_2147907999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.KZAA!MTB"
        threat_id = "2147907999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 05 00 11 05 13 06 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 17 73 ?? 00 00 0a 13 08 11 08 02 74 ?? 00 00 1b 16 02 14 72 d3 03 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_Q_2147908309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.Q!MTB"
        threat_id = "2147908309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 d0 ?? 00 00 1b 28 ?? 00 00 0a a2 14 28 ?? 00 00 0a 14 17 8d ?? 00 00 01 25 16 11 08 74 ?? 00 00 1b 11 07 17 da 9a a2 6f ?? 00 00 0a 28 ?? 00 00 0a a2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_LGAA_2147908420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.LGAA!MTB"
        threat_id = "2147908420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 08 11 08 74 ?? 00 00 01 02 74 ?? 00 00 1b 16 02 14 72 d3 03 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 11 08 75 ?? 00 00 01 6f ?? 00 00 0a 11 07 74 ?? 00 00 01 6f ?? 00 00 0a 0c de 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_LIAA_2147908477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.LIAA!MTB"
        threat_id = "2147908477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a a2 14 14 16 17 28 ?? 00 00 0a 09 14 72 89 0f 00 70 18 8d ?? 00 00 01 25 16 09 25 13 05 14 72 7b 0f 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a a2 25 17 09 25 13 06 14}  //weight: 2, accuracy: Low
        $x_2_2 = {01 02 16 02 8e 69 6f ?? 00 00 0a 11 0c 74 ?? 00 00 01 6f ?? 00 00 0a de 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_LKAA_2147908508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.LKAA!MTB"
        threat_id = "2147908508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 07 73 ?? 00 00 0a 13 04 11 04 74 ?? 00 00 01 11 07 75 ?? 00 00 01 17 73 ?? 00 00 0a 13 05 11 05 74 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 11 05 74 ?? 00 00 01 6f ?? 00 00 0a 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 0c}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MUAA_2147910321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MUAA!MTB"
        threat_id = "2147910321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 73 ?? ?? 00 0a 13 05 11 05 74 ?? 00 00 01 11 04 75 ?? 00 00 01 17 73 ?? ?? 00 0a 13 07 11 07 75 ?? 00 00 01 02 16 02 8e 69 6f ?? ?? 00 0a 11 07 ?? ?? 00 00 01 6f ?? ?? 00 0a de 16}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_KAB_2147910957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.KAB!MTB"
        threat_id = "2147910957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1d 5d 16 fe 01 13 05 11 05 2c 0c 02 11 04 02 11 04 91 1f 53 61 b4 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_NOAA_2147911387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.NOAA!MTB"
        threat_id = "2147911387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 11 05 6f ?? 01 00 0a 13 06 73 ?? 01 00 0a 0d 09 11 06 17 73 ?? 01 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 01 00 0a 11 04 6f ?? 01 00 0a 09 6f ?? 01 00 0a 0c de 23}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_OGAA_2147912054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.OGAA!MTB"
        threat_id = "2147912054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 13 05 11 05 6f ?? 01 00 0a 13 06 73 ?? 00 00 0a 0d 09 11 06 17 73 ?? 01 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 01 00 0a 00 11 04 6f ?? 01 00 0a 00 09 6f ?? 00 00 0a 0c de 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ORAA_2147912420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ORAA!MTB"
        threat_id = "2147912420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0c 02 11 05 02 11 05 91 1f ?? 61 b4 9c 11 05 17 d6 13 05 11 05 11 04 31 db}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_OSAA_2147912421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.OSAA!MTB"
        threat_id = "2147912421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 06 73 ?? 01 00 0a 0d 09 11 06 17 73 ?? 01 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 01 00 0a 00 11 04 6f ?? 01 00 0a 00 09 6f ?? 01 00 0a 0c de 1c}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_OZAA_2147912604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.OZAA!MTB"
        threat_id = "2147912604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 14 13 04 00 09 08 17 28 ?? ?? 00 06 13 04 11 04 02 7b ?? ?? 00 04 16 02 7b ?? ?? 00 04 8e 69 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 00 09 13 05 11 05 0a de 28}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 18 d8 1f 18 30 05 06 18 d8 2b 02 1f 18 0a 00 06 1f 18 5d 16 fe 01 0c 08 2c e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 20 c8 01 00 00 61 13 04 11 04 18 62 13 04 11 04 07 19 62 61 13 04 11 04 13 05 16 13 06 2b 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 0b 2b 0c 07 18 d8 1f 18 28 52 00 00 0a 0b 00 07 1f 18 5d 16 fe 01 0c 08 2c e9 07 0a 2b 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 19 5d 16 fe 01 13 07 11 07 2c 0d 06 11 06 06 11 06 91 1f 26 61 b4 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 1d 5d 16 fe 01 13 07 11 07 2c 0d 06 11 06 06 11 06 91 1f 4a 61 b4 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 18 0a 72 45 01 00 70 28 a7 00 00 06 0b 07 74 0c 00 00 1b 28 68 00 00 06 00 de 0f 25 28 38 00 00 0a 0c 00 28 52 00 00 0a de 00 00 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 19 d8 0a 06 1f 18 fe 02 0c 08 2c 0f 1f 18 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 0b 00 00 00 06 1f 18 5d 16 fe 03 0d 09 2d d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 8e 69 17 da 0b 16 0c 2b 1a 08 1b 5d 16 fe 01 0d 09 2c 0b 02 08 02 08 91 1f 32 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2 02 0a 2b 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2b 1e 06 19 d8 0a 06 1f 18 fe 02 0c 08 2c 0f 1f 18 0a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 00 00 00 06 1f 18 5d 16 fe ?? 0d 09 ?? d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 17 da 17 d6 8d 03 00 00 01 0b 07 ?? 0a 00 00 1b 06 17 da 72 d0 2d 00 70 28 df 01 00 06 28 39 00 00 06 a2 07 74 0a 00 00 1b 06 28 b1 00 00 06 de 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 18 0a 72 ?? ?? 00 70 0c 08 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? ?? 00 0a 28 ?? ?? 00 06 0b 07 74 ?? ?? 00 1b 28 ?? ?? 00 06 00 de 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 28 38 02 00 06 0b 07 06 17 da 72 d2 61 00 70 28 8d 00 00 06 28 33 02 00 06 a2 07 06 28 39 02 00 06 00 de 10 25 28 33 00 00 0a 13 05 00 28 85 00 00 0a de 00 00 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 0a 00 06 1f 18 fe 02 16 fe 01 0c 08 2c 06 1f 18 0a 00 2b 10 00 06 1f 18 fe 04 0d 09 2c 04 1f 18 0a 00 00 00 00 06 1f 18 5d 16 fe 01 13 04 11 04 2c cf 06 17 da 17 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 06 17 8d 02 00 00 01 25 16 06 ?? ?? 00 00 01 a2 25 13 06 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 07 28 ?? 00 00 0a 13 08 [0-2] 13 0e 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 20 cc 00 00 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 0b 07 74 ?? ?? 00 1b 28 ?? ?? 00 06 00 de 0f 25 28 ?? ?? 00 0a 0c 00 28 ?? ?? 00 0a de 00 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 16 9a 14 [0-16] 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 17 8d ?? ?? 00 01 25 16 03 8c ?? ?? 00 01 a2 25 0b 14 14 17 8d ?? ?? 00 01 25 16 17 9c 25 0c 28 ?? ?? 00 0a 0d ?? 13 09 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 17 da 17 d6 8d ?? ?? 00 01 0c 72 ?? ?? 00 70 0d 09 28 ?? ?? 00 06 13 04 11 04 28 ?? ?? 00 06 13 05 08 06 17 da 11 05 28 ?? ?? 00 0a a2 08 06 28 ?? ?? 00 06 00 de 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 ec 01 00 06 28 37 00 00 0a 10 00 02 28 37 00 00 0a 28 ed 01 00 06 28 37 00 00 0a 0a 02 74 1c 00 00 01 06 28 69 00 00 0a 28 ee 01 00 06 28 05 01 00 06 28 3d 02 00 06 28 37 00 00 0a 28 19 02 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 11 05 14 72 ?? ?? 00 70 17 8d ?? ?? 00 01 25 16 06 72 ?? ?? 00 70 28 ?? ?? 00 0a a2 14 14 14 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 06 11 06 2c 0e 08 11 05 28 ?? ?? 00 0a 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 10 0a 06 17 da 06 28 ?? ?? 00 06 80 ?? ?? 00 04 06 20 ?? ?? 00 00 d8 80 ?? ?? 00 04 72 ?? ?? ?? ?? 28 ?? ?? 00 06 7e ?? ?? 00 04 28 ?? ?? 00 06 80 ?? ?? 00 04 28 ?? ?? 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {25 16 02 a2 25 17 16 ?? ?? ?? ?? ?? a2 25 18 02 8e 69 ?? ?? ?? ?? ?? a2 25 13 08 14 14 19}  //weight: 100, accuracy: Low
        $x_100_2 = {0d 07 06 17 da 09 28 ?? ?? ?? ?? a2 07 06 28 ?? ?? ?? ?? 00 de 1f}  //weight: 100, accuracy: Low
        $x_1_3 = ".g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 ba 00 00 06 0a 06 2c 02 2b 01 00 00 73 24 00 00 0a 28 4d 00 00 0a 28 69 01 00 06 00 de 0f 25 28 47 00 00 0a 0b 00 28 60 00 00 0a de 00 00 2a}  //weight: 10, accuracy: High
        $x_1_2 = {00 28 6f 00 00 06 16 fe 01 0b 07 2c 04 17 0a 2b 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_22
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 17 da 17 d6 8d ?? ?? 00 01 0b 72}  //weight: 10, accuracy: Low
        $x_10_2 = {b7 0a 06 17 da 17 d6 8d ?? ?? 00 01 0b 20 ?? ?? ?? ?? 8c ?? ?? 00 01 0c 72 ?? ?? 00 70 72 ?? ?? 00 70 72 ?? ?? 00 70 28}  //weight: 10, accuracy: Low
        $x_1_3 = "WindowsApp1.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_23
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "WindowsApp1.Resources" wide //weight: 100
        $x_10_2 = {72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 [0-16] 2e 00 (70 00 6e 00|6a 00 70 00)}  //weight: 10, accuracy: Low
        $x_10_3 = {1f 18 0a 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b}  //weight: 10, accuracy: Low
        $x_1_4 = ".g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_24
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 33 00 00 0a 0a 06 28 33 00 00 0a 28 ?? 01 00 06 de 0e 25 28 ?? 00 00 0a 0b 28 ?? 00 00 0a de 00}  //weight: 1, accuracy: Low
        $x_1_2 = {28 34 00 00 0a 0a 06 28 34 00 00 0a 28 ?? 01 00 06 de 0e 25 28 ?? 00 00 0a 0b 28 ?? 00 00 0a de 00}  //weight: 1, accuracy: Low
        $x_1_3 = {28 39 00 00 0a 0a 06 28 39 00 00 0a 28 ?? 01 00 06 00 de 0f 25 28 ?? 00 00 0a 0b 00 28 ?? 00 00 0a de 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_25
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "104"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {0b 07 06 17 da 72 ?? ?? ?? ?? 28}  //weight: 100, accuracy: Low
        $x_100_2 = {0a 06 2c 02 2b 01 00 00 73 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28}  //weight: 100, accuracy: Low
        $x_100_3 = {25 16 02 a2 0c 07 72 ?? ?? ?? ?? 20 00 01 00 00 14 14 08 6f}  //weight: 100, accuracy: Low
        $x_100_4 = {a2 07 19 07 18 9a 74 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28}  //weight: 100, accuracy: Low
        $x_1_5 = "WindowsApp1.Resources" wide //weight: 1
        $x_3_6 = ".g.resources" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_26
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "106"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 1b 19 9a 28 ?? 00 00 0a 28 ?? ?? 00 06 26 de}  //weight: 100, accuracy: Low
        $x_1_2 = "Create__Instance__" ascii //weight: 1
        $x_1_3 = "Dispose__Instance__" ascii //weight: 1
        $x_1_4 = "System.Security.Cryptography" ascii //weight: 1
        $x_1_5 = "GetResourceString" ascii //weight: 1
        $x_1_6 = "CryptoStreamMode" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RP_2147913029_27
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RP!MTB"
        threat_id = "2147913029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "148"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptoStreamMode" ascii //weight: 1
        $x_1_2 = "EndInvoke" ascii //weight: 1
        $x_1_3 = "BeginInvoke" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "get_Key" ascii //weight: 1
        $x_1_6 = "set_Key" ascii //weight: 1
        $x_1_7 = "ContainsKey" ascii //weight: 1
        $x_1_8 = "System.Security.Cryptography" ascii //weight: 1
        $x_10_9 = "Create__Instance__" ascii //weight: 10
        $x_10_10 = "Dispose__Instance__" ascii //weight: 10
        $x_100_11 = "ConnectionTester" ascii //weight: 100
        $x_10_12 = "TestConnection Lansweeper" ascii //weight: 10
        $x_10_13 = ", WindowsApp1," ascii //weight: 10
        $x_100_14 = "WindowsApp1.WeatherApp+" ascii //weight: 100
        $x_10_15 = "WindowsApp1.AirplaneWeatherControl+" ascii //weight: 10
        $x_10_16 = "WindowsApp1.MLWeatherForecast+" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 4 of ($x_10_*) and 8 of ($x_1_*))) or
            ((1 of ($x_100_*) and 5 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkTortilla_SPBF_2147913107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SPBF!MTB"
        threat_id = "2147913107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {08 1d 5d 16 fe 01 0d 09 2c 0b 02 08 02 08 91 1f 4c 61 b4 9c 00 00 08 17 d6 0c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SPZF_2147913379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SPZF!MTB"
        threat_id = "2147913379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 09 07 6f ?? 00 00 0a 00 09 19 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 73 8e 00 00 0a 13 04 11 04 11 07 17 73 8f 00 00 0a 13 05 11 05 02 16 02 8e 69}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_PSAA_2147913986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.PSAA!MTB"
        threat_id = "2147913986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 73 71 01 00 0a 0d 14 13 04 00 09 08 17 28 ?? 01 00 06 13 04 11 04 02 7b ?? 01 00 04 16 02 7b ?? 01 00 04 8e 69 6f ?? 01 00 0a 00 11 04 6f ?? 01 00 0a 00 09 13 05 11 05 0a de 28 00 11 04 14 fe 03 13 06 11 06 2c 08 11 04 6f}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_PXAA_2147914142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.PXAA!MTB"
        threat_id = "2147914142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {a2 02 03 1c da 14 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? ?? 00 70 17 8d ?? 00 00 01 25 16 02 25 0b 03 17 da 25 0c 9a a2 25 0d 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 04 28 ?? 00 00 0a 11 04 16 91 2d 02}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_QJAA_2147914637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.QJAA!MTB"
        threat_id = "2147914637"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0c 07 14 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? ?? 00 70 17 8d ?? 00 00 01 25 16 08 28 ?? 01 00 06 28 ?? 00 00 06 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 06 28 ?? 01 00 06 00 de 10}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_QZAA_2147915349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.QZAA!MTB"
        threat_id = "2147915349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 05 00 73 ?? 00 00 0a 13 06 00 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 02 74 ?? 00 00 1b 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 00 de 0e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RBAA_2147915367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RBAA!MTB"
        threat_id = "2147915367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 00 73 ?? 00 00 0a 13 05 00 11 05 11 04 17 73 ?? 00 00 0a 13 07 11 07 02 16 02 28 ?? 00 00 2b 6f ?? 00 00 0a 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 00 de 0e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ROAA_2147916120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ROAA!MTB"
        threat_id = "2147916120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 06 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 17 73 ?? 00 00 0a 13 08 11 08 02 74 ?? 00 00 1b 16 02 14 72 2d 07 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 00 de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SQAA_2147917023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SQAA!MTB"
        threat_id = "2147917023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 07 73 ?? 01 00 0a 13 04 11 04 11 07 17 73 ?? 01 00 0a 13 05 11 05 14 72 23 20 00 70 19 8d ?? 00 00 01 25 16 02 a2 25 17 16 8c ?? 00 00 01 a2 25 18 02 8e 69}  //weight: 3, accuracy: Low
        $x_2_2 = {11 05 14 72 2f 20 00 70 16 8d ?? 00 00 01 14 14 14 17 28 ?? 00 00 0a 26 11 04 6f ?? 01 00 0a 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MBXK_2147917220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MBXK!MTB"
        threat_id = "2147917220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 00 63 00 75 00 5e 00 64 00 6d 00 73 00 6a 00 5b 00 66 00 00 15 75 00 71 00 2f 00 2a 00 29 00 74 00 28 00 6f 00 23 00 65 00 00 15 23 00 21 00 6b 00 6d 00 70 00 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MBXL_2147917221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MBXL!MTB"
        threat_id = "2147917221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {35 37 65 39 39 39 66 66 33 64 31 7d 00 3c 4d 6f 64 75 6c 65 3e 00 6f 70 69 6b 6a 66 6d 6e 63 78 63 7a 33 64 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SYAA_2147917438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SYAA!MTB"
        threat_id = "2147917438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 75 ?? 00 00 1b 6f ?? 00 00 0a 17 da 0c 1d 13 05 2b ab 16 0d 1b 13 05 2b a4 07 75 ?? 00 00 1b 09 07 75 ?? 00 00 1b 09 6f ?? 00 00 0a 1f 33 61 b4 6f ?? 00 00 0a 1c 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_TIAA_2147917836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.TIAA!MTB"
        threat_id = "2147917836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1d 13 0b 38 ?? ff ff ff 11 04 74 ?? 00 00 01 09 74 ?? 00 00 01 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 75 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 16 13 0b 38 ?? ff ff ff 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 11 04 75 ?? 00 00 01 6f d8 00 00 0a 0c 1e 13 0b 38}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_TJAA_2147917868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.TJAA!MTB"
        threat_id = "2147917868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1e 13 0b 2b 97 11 04 75 ?? 00 00 01 09 75 ?? 00 00 01 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 74 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 1d 13 0b 38 ?? ff ff ff 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 0c 1a 13 0b 38}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_TOAA_2147918076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.TOAA!MTB"
        threat_id = "2147918076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {ff 11 04 75 ?? 00 00 01 09 74 ?? 00 00 01 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 74 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 19 13 0b 38 ?? ff ff ff 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 11 04 75 ?? 00 00 01 6f ?? 00 00 0a 0c 17 13 0b 38}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_UEAA_2147919158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.UEAA!MTB"
        threat_id = "2147919158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 11 09 74 ?? 00 00 01 6f ?? 00 00 0a 11 09 75 ?? 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 13 0a}  //weight: 2, accuracy: Low
        $x_3_2 = {02 07 75 25 00 00 1b 6f ?? 00 00 0a 11 0a 74 ?? 00 00 01 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 16 13 19 2b b5}  //weight: 3, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MBXS_2147919377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MBXS!MTB"
        threat_id = "2147919377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YFSFU7xIlY5N6sDAHJkOYL.Resour" ascii //weight: 3
        $x_2_2 = {63 74 6f 72 00 7a 58 54 77 54 6e 64 6e 51 67 41 70 31 51 4a 46 4d 6f 51 4f 6b 41 38 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_UPAA_2147919755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.UPAA!MTB"
        threat_id = "2147919755"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 09 07 6f ?? 00 00 0a 6f ?? 01 00 0a 00 09 19 6f ?? 01 00 0a 00 09 6f ?? 01 00 0a 13 07 73 ?? 00 00 0a 13 04 11 04 11 07 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 00 11 05 6f ?? 01 00 0a 00 11 04 6f ?? 00 00 0a 0c 00 00 de 39}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_VCAA_2147920003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.VCAA!MTB"
        threat_id = "2147920003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 02 16 02 8e 69 6f ?? 00 00 0a 11 08 74 ?? 00 00 01 6f ?? 00 00 0a 16 13 13 2b bf 11 07 75 ?? 00 00 01 6f ?? 00 00 0a 0d de 49}  //weight: 3, accuracy: Low
        $x_2_2 = {11 07 75 84 00 00 01 11 06 75 ?? 00 00 01 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 08}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_VJAA_2147920212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.VJAA!MTB"
        threat_id = "2147920212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 06 11 06 08 6f ?? 00 00 0a 00 11 06 08 6f ?? 00 00 0a 00 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 0d de 0e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_WGAA_2147920812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.WGAA!MTB"
        threat_id = "2147920812"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 02 74 15 00 00 01 06 28 ?? 00 00 0a 28 ?? 00 00 06 0b 07 74 ?? 00 00 1b 28 ?? 01 00 06 74 ?? 00 00 1b 0c 08 28 ?? 00 00 06 0d 09 28 ?? 00 00 0a 28 ?? 00 00 06 74 ?? 00 00 01 13 04 11 04 6f ?? 00 00 0a 13 05 11 05 fe 0b 00 00 02 74 ?? 00 00 1b 28 ?? 01 00 06 26 de 10}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_WKAA_2147920935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.WKAA!MTB"
        threat_id = "2147920935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 1b 13 0f 2b 82 09 74 ?? 00 00 01 19 6f ?? 01 00 0a 09 75 ?? 00 00 01 6f ?? 01 00 0a 13 07 16 13 0f 38 ?? ff ff ff 73 ?? 00 00 0a 13 04 11 04 75 ?? 00 00 01 11 07 75 ?? 00 00 01 17 73 ?? 00 00 0a 13 05 11 05 74 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 1e 13 0f 38 ?? ff ff ff 11 05 74 ?? 00 00 01 6f ?? 01 00 0a 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 0c 1f 09 13 0f 38}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_XCAA_2147921697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.XCAA!MTB"
        threat_id = "2147921697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 2c 07 7e ?? 00 00 04 2b 16 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 16 28 ?? 00 00 2b 0b 07 14 72 e5 00 00 70 18 8d ?? 00 00 01 25 17 17 8d ?? 00 00 01 25 16 02 a2 a2 14 14 14 28 ?? 00 00 0a 0a de 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_YHAA_2147922430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.YHAA!MTB"
        threat_id = "2147922430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a a2 25 17 17 8c 64 00 00 01 a2 25 18 17 8c 64 00 00 01 a2 25 13 04 14 14 19 8d 64 00 00 01 25 16 17 9c 25 13 05 28 ?? 00 00 0a 13 06 11 05 16 91 2d 02 2b 23 11 04 16 9a}  //weight: 3, accuracy: Low
        $x_2_2 = {01 11 0c 16 11 0c 8e 69 6f ?? 01 00 0a 13 0d 11 0d 16 fe 02 13 0f 11 0f 2c 0e 11 0b 11 0c 16 11 0d 6f ?? 01 00 0a 00 00 00 00 11 0d 16 fe 02 13 10 11 10 2d c5 11 0b 6f ?? 01 00 0a 13 0e 11 0e 28 ?? 01 00 0a 00 11 0e 0a 2b 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_YPAA_2147922622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.YPAA!MTB"
        threat_id = "2147922622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 18 9a 14 72 24 27 00 70 17 8d ?? 00 00 01 25 16 1f 18 8c ?? 00 00 01 a2 14 14 14 28 ?? 00 00 0a 14 72 36 27 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 16 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 14 72 16 27 00 70 18 8d ?? 00 00 01 25 17 7e ?? 00 00 04 a2 25 13 07 14 14 18 8d ?? 00 00 01 25 17 17 9c 25 13 08 17 28 ?? 00 00 0a 26 11 08 17 91 2d 02}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SEDA_2147922845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SEDA!MTB"
        threat_id = "2147922845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 08 6f ?? ?? ?? 0a 00 11 06 08 6f ?? ?? ?? 0a 00 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 6f ?? ?? ?? 0a 17 73 ?? 01 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 08 6f ?? ?? ?? 0a 00 11 07 6f ?? ?? ?? 0a 0d de 0e}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_YXAA_2147922937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.YXAA!MTB"
        threat_id = "2147922937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 13 04 2b 2c 11 04 1c 5d 16 fe 01 13 05 11 05 2c 0f 08 11 04 07 11 04 91 1f 3f 61 b4 9c 00 2b 0a 00 08 11 04 07 11 04 91 9c 00 11 04 17 d6 13 04 11 04 09 31 cf}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZFAA_2147923317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZFAA!MTB"
        threat_id = "2147923317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 1d 5d 2c 03 03 2b 04 03 1f 4f 61 b4 0a 2b 00 06 2a}  //weight: 3, accuracy: High
        $x_2_2 = {08 14 72 79 23 00 70 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 01 6f ?? 00 00 0a 13 08 2b 41 11 08 6f ?? 00 00 0a 28 ?? 00 00 0a 13 09 00 11 09 14 72 8f 23 00 70 18 8d 06 00 00 01 25 17 16 8d 06 00 00 01 a2 14 14 14 17 28 ?? 00 00 0a 26 de 1c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SPDA_2147923337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SPDA!MTB"
        threat_id = "2147923337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 14 0d 14 13 04 14 13 05 14 13 06 00 28 ?? 00 00 0a 13 04 11 04 14 fe 03 13 07 11 07 2c 2a 11 04 08 6f ?? 00 00 0a 00 11 04 08 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? 00 00 0a 0a de 53 00 de 4b}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZNAA_2147923540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZNAA!MTB"
        threat_id = "2147923540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 11 06 02 74 ?? 00 00 1b 16 02 14 72 85 24 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 07 74 ?? 00 00 1b 28 ?? 00 00 06 14 72 93 24 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 74 ?? 00 00 1b 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZRAA_2147923716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZRAA!MTB"
        threat_id = "2147923716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 14 72 41 0c 00 70 18 8d ?? 00 00 01 25 16 09 25 13 05 14 72 33 0c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a a2 25 17 09 25 13 06 14 72 3b 0c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a a2 25 13 07 14 14 18 8d ?? 00 00 01 25 16 17 9c 25 17 17 9c 25 13 08 28 ?? 00 00 0a 13 09 16 13 10 38}  //weight: 3, accuracy: Low
        $x_2_2 = "L o a d" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZUAA_2147923860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZUAA!MTB"
        threat_id = "2147923860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 17 8d 03 00 00 01 25 16 03 a2 25 0b 14 14 17 8d 87 00 00 01 25 16 17 9c 25 0c 28 ?? 00 00 0a 08 75 09 00 00 1b 16 91 2d 02 2b 11 07}  //weight: 3, accuracy: Low
        $x_2_2 = {06 13 07 11 07 7e 13 01 00 04 1f 20 7e 13 01 00 04 1f 20 94 7e 13 01 00 04 20 ab 00 00 00 94 61 20 db 00 00 00 5f 9e 2c 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZWAA_2147923976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZWAA!MTB"
        threat_id = "2147923976"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 14 72 85 34 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 05 11 04 11 05 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 0a 11 09 12 0a 28 ?? 01 00 0a 13 0c 11 0c 2d c4 11 04 6f ?? 01 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0a 2b 00 06 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 0c 08 14 72 63 34 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 13 07 11 07 2c 1d 08 14 72 6b 34 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_APBA_2147924521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.APBA!MTB"
        threat_id = "2147924521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 09 07 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 00 09 19 6f ?? 00 00 0a 00 00 73 ?? 00 00 0a 13 04 09 6f ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0c 11 04 08 16 08 8e 69 6f ?? 00 00 0a 00 de 0e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AHCA_2147925075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AHCA!MTB"
        threat_id = "2147925075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 14 fe 03 13 06 11 06 2c 27 09 07 6f ?? 00 00 0a 00 09 07 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 00 00 0a 0a de 51 00 de 49 00 09 14 fe 03 13 08 11 08 2c 07}  //weight: 3, accuracy: Low
        $x_1_2 = "RLRoRaRdR" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ARCA_2147925741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ARCA!MTB"
        threat_id = "2147925741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 1f 18 5d 16 fe 01 0b 07 2c 04 14 0a 2b 2a 00 02 19 d8 10 00 02 1f 18 fe 02 0c 08 2c 11 1f 18 10 00 72 0e 3b 00 70 28 ?? 01 00 06 0a 2b 0a 00 02 28 ?? 02 00 06 0a 2b 00 06 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 72 2d 21 00 70 17 8d ?? 00 00 01 25 16 02 a2 25 0c 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0d 28 ?? 00 00 0a 09 16 91 2d 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AJDA_2147926217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AJDA!MTB"
        threat_id = "2147926217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 1c 13 07 2b 8f 11 04 1f 09 5d 16 fe 01 13 05 11 05 2c 08 1d 13 07 38 ?? ff ff ff 1a 2b f6 08 74 ?? 00 00 1b 07 75 ?? 00 00 1b 11 04 91 20 c9 00 00 00 61 b4 6f ?? 01 00 0a 1e 13 07 38 ?? ff ff ff 17 13 07 38 ?? ff ff ff 08 75 ?? 00 00 1b 07 74 ?? 00 00 1b 11 04 91 6f ?? 01 00 0a 17 13 07 38 ?? ff ff ff 11 04 17 d6 13 04 1c 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AQDA_2147926426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AQDA!MTB"
        threat_id = "2147926426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 75 6a 00 00 01 02 74 0b 00 00 1b 16 02 14 1e d0 03 00 00 02 28 ?? 00 00 0a 20 a7 8c 9d 3e 28 ?? 02 00 06 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 13 06 17 13 0e 2b 9d}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ATDA_2147926533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ATDA!MTB"
        threat_id = "2147926533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 8e 69 17 da 0d 16 13 04 1f 0c 13 08 2b b6 11 04 17 5d 16 fe 01 13 05 11 05 2c 05 18 13 08 2b a4 1d 2b f9 02 11 04 02 11 04 91 20 d0 00 00 00 61 b4 9c 1d 13 08 2b 8d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AIEA_2147926924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AIEA!MTB"
        threat_id = "2147926924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 13 07 16 13 08 ?? 13 11 2b c0 11 07 74 0b 00 00 1b 11 08 9a 13 09 07 75 0c 00 00 1b 11 09 75 4b 00 00 01 1f 10 28 ?? 00 00 0a 6f 6d 00 00 0a}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 1d 13 13 2b 91 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 13 0c 11 0c 74 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 0a dd}  //weight: 2, accuracy: Low
        $x_2_3 = {11 08 11 07 74 0b 00 00 1b 8e 69 fe 04 13 0a}  //weight: 2, accuracy: High
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AMCO_2147927685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AMCO!MTB"
        threat_id = "2147927685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 02 16 02 8e 69 6f ?? 00 00 0a 13 06 ?? 13 ?? 38 25 00 11 04 74 ?? 00 00 01 6f ?? 00 00 0a 13 05 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SPJF_2147927697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SPJF!MTB"
        threat_id = "2147927697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 07 73 ?? 00 00 0a 13 04 11 04 11 07 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 0c 00 00 de 39}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPZ_2147927790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPZ!MTB"
        threat_id = "2147927790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "98"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_PID" ascii //weight: 1
        $x_10_2 = "set_AntiVM" ascii //weight: 10
        $x_10_3 = "set_InjectionPersistence" ascii //weight: 10
        $x_1_4 = "set_StartupPersistence" ascii //weight: 1
        $x_10_5 = "set_AntiSandBoxie" ascii //weight: 10
        $x_10_6 = "set_FakeMessageTitle" ascii //weight: 10
        $x_1_7 = "set_InstallationFileName" ascii //weight: 1
        $x_1_8 = "set_WatchDogName" ascii //weight: 1
        $x_1_9 = "set_InstallationKeyName" ascii //weight: 1
        $x_1_10 = "set_KeepAlive" ascii //weight: 1
        $x_10_11 = "set_HiddenStartupReg" ascii //weight: 10
        $x_1_12 = "set_InstallationRegisteryPath" ascii //weight: 1
        $x_1_13 = "add_Click" ascii //weight: 1
        $x_1_14 = "PerformClick" ascii //weight: 1
        $x_1_15 = "set_InstallFolder" ascii //weight: 1
        $x_1_16 = "set_InstallationFolder" ascii //weight: 1
        $x_1_17 = "set_TempFolder" ascii //weight: 1
        $x_1_18 = "set_StartupFolder" ascii //weight: 1
        $x_1_19 = "Class5_Decrypter" ascii //weight: 1
        $x_10_20 = "Class8_AntiVMs" ascii //weight: 10
        $x_1_21 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_22 = "set_FakeMessageShow" ascii //weight: 1
        $x_1_23 = "set_FakeMessageIconIndex" ascii //weight: 1
        $x_10_24 = "set_InjectionHostIndex" ascii //weight: 10
        $x_1_25 = "set_FakeMessageBody" ascii //weight: 1
        $x_10_26 = "set_HiddenStartupKey" ascii //weight: 10
        $x_1_27 = "%InjectionPersist%" ascii //weight: 1
        $x_1_28 = "%StartupPersist%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_10_*) and 18 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_DarkTortilla_RPA_2147928267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPA!MTB"
        threat_id = "2147928267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 [0-6] 2e 67 2e 72 65 73 6f 75 72 63 65 73 00 00 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPB_2147928268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPB!MTB"
        threat_id = "2147928268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {00 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 [0-6] 2e 67 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 00 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPAA_2147929160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPAA!MTB"
        threat_id = "2147929160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 ?? 2e ?? 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 [0-6] 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPAB_2147929161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPAB!MTB"
        threat_id = "2147929161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 ?? 2e ?? 2e 72 65 73 6f 75 72 63 65 73 00 [0-6] 2e 67 2e 72 65 73 6f 75 72 63 65 73 00 [0-6] 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPAC_2147929162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPAC!MTB"
        threat_id = "2147929162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 [0-6] 2e 67 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 00 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPAD_2147929163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPAD!MTB"
        threat_id = "2147929163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 [0-6] 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 00 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPAE_2147929164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPAE!MTB"
        threat_id = "2147929164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 [0-6] 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_RPAF_2147929165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.RPAF!MTB"
        threat_id = "2147929165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 [0-6] 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 100, accuracy: Low
        $x_1_2 = "WindowsApp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AUHA_2147929343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AUHA!MTB"
        threat_id = "2147929343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 1d 13 09 2b 8a 11 05 17 d6 13 05 1f ?? 13 09 38 ?? ff ff ff 11 05 11 04}  //weight: 5, accuracy: Low
        $x_5_2 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 1f 09 13 09 38 ?? ff ff ff 11 05 17 d6 13 05 1f 0c 13 09 38 ?? ff ff ff 11 05 11 04}  //weight: 5, accuracy: Low
        $x_5_3 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 19 13 09 2b 8b 11 05 17 d6 13 05 1f 0b 13 09 38 ?? ff ff ff 11 05 11 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AZHA_2147929772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AZHA!MTB"
        threat_id = "2147929772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 1f 09 13 09 2b 8a 11 05 17 d6 13 05 1c 13 09 38 ?? ff ff ff 11 05 11 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ARAZ_2147933690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ARAZ!MTB"
        threat_id = "2147933690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 19 5d 16 fe 01 13 06 11 06 2c 58 06}  //weight: 2, accuracy: High
        $x_2_2 = {07 17 d6 0b 11 05 15 d6 13 05 11 05 16 3c 87}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SK_2147936255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SK!MTB"
        threat_id = "2147936255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 14 6f 44 01 00 0a 00 00 11 06 6f 9e 02 00 0a 11 05 fe 04 13 0a 11 0a 2d e5}  //weight: 2, accuracy: High
        $x_2_2 = "Hacrajiq.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MKT_2147938160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MKT!MTB"
        threat_id = "2147938160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 50 28 74 00 00 2b 0b 12 01 28 a6 02 00 0a 18 8d 06 00 00 01 25 16 09 8c 60 00 00 01 a2 25 17 03 50 28 ?? 00 00 2b 0b 12 01 28 a6 02 00 0a 17 8d 06 00 00 01 25 16 09 8c 60 00 00 01 a2 14 28 d3 01 00 0a 1f 15 8c 60 00 00 01 28 ?? 02 00 0a a2 14 16 17 28 ?? 02 00 0a 00 09 17 d6 0d 09 08 31 9e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MKB_2147938275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MKB!MTB"
        threat_id = "2147938275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0d 09 14 fe 03 13 06 11 06 2c 31 09 07 6f ?? 01 00 0a 6f ?? 00 00 0a 00 09 07 6f ?? 01 00 0a 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 01 00 0a 0a de 51 00 de 49}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_CHV_2147938676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.CHV!MTB"
        threat_id = "2147938676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 07 6f b2 04 00 0a 00 09 07 6f b3 04 00 0a 00 09 19 6f b4 04 00 0a 00 09 6f b5 04 00 0a 13 07 73 32 04 00 0a 13 04 11 04 11 07 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZRT_2147939135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZRT!MTB"
        threat_id = "2147939135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 20 80 00 00 00 6f ?? 01 00 0a 00 07 20 80 00 00 00 6f ?? 01 00 0a 00 07 19 6f ?? 01 00 0a 00 07 03 6f ?? 01 00 0a 00 07 03 6f ?? 01 00 0a 00 00 07 6f ?? 01 00 0a 0c 02 73 6c 01 00 0a 0d 09 08 16 73 6d 01 00 0a 13 04 11 04 73 6e 01 00 0a 13 05 11 05 02 8e 69 6f 6f 01 00 0a 0a de 52}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_APRA_2147939703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.APRA!MTB"
        threat_id = "2147939703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 09 11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 00 11 09 11 09 6f ?? 02 00 0a 11 09 6f ?? 02 00 0a 6f ?? 02 00 0a 13 0a 02 07 6f ?? 02 00 0a 11 0a 28 ?? 00 00 06 28 ?? 00 00 2b 6f ?? 01 00 0a 00 de 0e}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_WQ_2147939736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.WQ!MTB"
        threat_id = "2147939736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 02 11 05 02 11 05 91 ?? ?? ?? ?? ?? 61 b4 9c 11 05 17 d6 13 05 11 05 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZGW_2147940270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZGW!MTB"
        threat_id = "2147940270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0a 00 09 09 6f ?? 01 00 0a 09 6f ?? 01 00 0a 6f ?? 01 00 0a 13 04 00 73 ?? 01 00 0a 13 05 00 11 05 11 04 17 73 ?? 01 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 01 00 0a 00 11 07 6f ?? 01 00 0a 00 de 0e}  //weight: 6, accuracy: Low
        $x_5_2 = {03 09 11 05 6f ?? 01 00 0a 13 06 02 11 06 04 28 ?? 00 00 0a 28 ?? 00 00 06 13 07 06 09 11 05 11 07}  //weight: 5, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZJW_2147940374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZJW!MTB"
        threat_id = "2147940374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {04 1f 09 5d 2c 03 03 2b 07 03 20 ed 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 6, accuracy: High
        $x_5_2 = {11 08 14 72 d3 71 00 70 18 8d ?? 00 00 01 25 17 17 8d ?? 00 00 01 25 16 07 a2 a2 14 14 14 28 ?? 01 00 0a 28 ?? 00 00 0a 13 09 11 09 6f ?? 02 00 0a 72 e1 71 00 70 6f ?? 02 00 0a 13 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AQSA_2147940529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AQSA!MTB"
        threat_id = "2147940529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0d 09 74 ?? 00 00 01 14 fe 03 13 06 11 06 2c 05 16 13 0e 2b bf 1b 2b f9 09 74 ?? 00 00 01 07 74 ?? 00 00 1b 6f ?? ?? 00 0a 09 75 ?? 00 00 01 07 75 ?? 00 00 1b 6f ?? ?? 00 0a 17 13 0e 2b 95 09 75 ?? 00 00 01 6f ?? ?? 00 0a 13 07 11 07 75 ?? 00 00 01 02 16 02 8e 69 6f ?? ?? 00 0a 0a dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AYSA_2147940763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AYSA!MTB"
        threat_id = "2147940763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 2c 08 02 8e 69 16 fe 01 2b 01 17 2c 04 14 0a 2b 71 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 0b 73 ?? 01 00 0a 0d 09 75 ?? 00 00 01 07 74 ?? 00 00 1b 28 ?? 02 00 06 09 75 ?? 00 00 01 6f ?? 01 00 0a 13 04 11 04 75 ?? 00 00 01 02 28 ?? 02 00 06 0a de 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {02 03 16 03 8e 69 6f ?? 01 00 0a 0b 07 75 ?? 00 00 1b 28 ?? 02 00 06 0a 06 75 ?? 00 00 1b 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_2147941270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MTS!MTB"
        threat_id = "2147941270"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTS: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 20 80 00 00 00 6f ?? 00 00 0a 00 07 20 80 00 00 00 6f ?? 00 00 0a 00 07 19 6f ?? 00 00 0a 00 07 03 6f ?? 00 00 0a 00 07 03 6f ?? 00 00 0a 00 00 07 6f ?? 00 00 0a 0c 02 73 92 00 00 0a 0d 09 08 16 73 93 00 00 0a 13 04 11 04 73 94 00 00 0a 13 05 11 05 02 8e 69 6f ?? 00 00 0a 0a de 52 00 11 05 2c 08 11 05 6f ?? 00 00 0a 00 dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BTT_2147941502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BTT!MTB"
        threat_id = "2147941502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b 13 0c 11 0c 45 07 00 00 00 31 00 00 00 25 00 00 00 00 00 00 00 42 00 00 00 3d 00 00 00 00 00 00 00 31 00 00 00 07 74 8a 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 07 74 8a 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 17 13 0c 2b b8 07 74 8a 00 00 01 19 6f ?? 00 00 0a 07 74 8a 00 00 01 03 6f ?? 00 00 0a 19 13 0c 2b 9b 07 75 8a 00 00 01 03 6f ?? 00 00 0a 07 75 8a 00 00 01 6f 92 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MPV_2147941594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MPV!MTB"
        threat_id = "2147941594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 74 3a 00 00 01 08 74 02 01 00 01 1f 20 6f ?? 03 00 0a 6f ?? 03 00 0a 09 75 3a 00 00 01 08 74 02 01 00 01 1f 10 6f 55 03 00 0a 6f 19 03 00 0a 19 13 0c 2b a8 09 75 3a 00 00 01 09 75 3a 00 00 01 6f ?? 03 00 0a 09 74 3a 00 00 01 6f ?? 03 00 0a 6f ?? 03 00 0a 13 04 16 13 0c 2b 80}  //weight: 5, accuracy: Low
        $x_4_2 = {11 07 75 03 01 00 01 02 16 02 8e 69 6f ?? 03 00 0a 11 07 74 03 01 00 01 6f ?? 03 00 0a 1b 13 10 2b bf}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZWV_2147941720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZWV!MTB"
        threat_id = "2147941720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {14 0a 2b 50 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 01 00 0a 0b 00 73 ?? 01 00 0a 0d 09 07 28 ?? 01 00 06 00 00 09 6f ?? 01 00 0a 13 04 11 04 02 28 ?? 01 00 06 0a de 1a 00 11 04 2c 08}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MZV_2147941813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MZV!MTB"
        threat_id = "2147941813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0b 11 0b 45 07 00 00 00 5d 00 00 00 5d 00 00 00 00 00 00 00 35 00 00 00 00 00 00 00 35 00 00 00 00 00 00 00 09 75 27 00 00 01 08 74 02 01 00 01 1f 20 6f ?? 03 00 0a 6f ?? 03 00 0a 09 75 27 00 00 01 08 74 02 01 00 01 1f 10 6f ?? 03 00 0a 6f ?? 03 00 0a 1b 13 0b 2b a8 09 75 27 00 00 01 09 74 27 00 00 01 6f ?? 03 00 0a 09 74 27 00 00 01 6f ?? 03 00 0a 6f ?? 03 00 0a 13 04 17 13 0b 2b 80}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ABVA_2147942110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ABVA!MTB"
        threat_id = "2147942110"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? ?? 00 0a 19 13 11 2b af 11 09 74 ?? 00 00 01 6f ?? ?? 00 0a 11 08 75 ?? 00 00 01 6f ?? ?? 00 0a 0d de 49}  //weight: 5, accuracy: Low
        $x_2_2 = {0a 11 04 75 ?? 00 00 01 20 80 00 00 00 6f ?? ?? 00 0a 1a 13 0d 2b 86 11 04 74 ?? 00 00 01 19 6f ?? ?? 00 0a 11 04 74 ?? 00 00 01 08 75 ?? 00 00 1b 6f ?? ?? 00 0a 17 13 0d 38 ?? ff ff ff 11 04 75 ?? 00 00 01 08 74 ?? 00 00 1b 6f ?? ?? 00 0a 11 04 75 ?? 00 00 01 6f ?? ?? 00 0a 13 06 19 13 0d 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MZL_2147942154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MZL!MTB"
        threat_id = "2147942154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 09 13 06 2b bd 02 28 ?? ?? 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 07 75 0d 00 00 1b 8e 69 17 da 0c 1b 13 06 2b 9c 16 0d 17 13 06 2b 95 07 74 0d 00 00 1b 09 91 16 fe 01 13 04 11 04 2c 08}  //weight: 5, accuracy: Low
        $x_4_2 = {07 75 0d 00 00 1b 0a 06 75 0d 00 00 1b 7e 86 00 00 04 1f 65 7e 86 00 00 04 1f 65 91 7e 13 01 00 04 1f 11 93 59 1f 7a 5f 9c 2a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZMU_2147942285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZMU!MTB"
        threat_id = "2147942285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 1f 0b 13 06 2b bd 02 28 ?? 01 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 07 75 0d 00 00 1b 8e 69 17 da 0c 19 13 06 2b 9c 16 0d 1a 13 06 2b 95 07 75 0d 00 00 1b 09 91 16 fe 01 13 04 11 04 2c 08}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AWM_2147942378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AWM!MTB"
        threat_id = "2147942378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 74 8d 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 07 74 8d 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 1c 13 0c 2b b8 07 75 8d 00 00 01 19 6f ?? 00 00 0a 07 74 8d 00 00 01 03 6f ?? 00 00 0a 17 13 0c 2b 9b 07 74 8d 00 00 01 03 6f ?? 00 00 0a 07 75 8d 00 00 01 6f ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
        $x_4_2 = {11 04 75 92 00 00 01 73 95 00 00 0a 13 05 19 13 14 11 14 45 05 00 00 00 10 00 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 11 05 74 94 00 00 01 02 8e 69 6f 96 00 00 0a 0a dd 78 01 00 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AUVA_2147942564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AUVA!MTB"
        threat_id = "2147942564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 14 0c 14 0d 14 13 04 14 13 05 00 28 ?? ?? 00 0a 0d 09 14 fe 03 13 06 11 06 2c 27 09 07 6f ?? ?? 00 0a 00 09 07 6f ?? ?? 00 0a 00 09 6f ?? ?? 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? ?? 00 0a 0a de 41 00 de 39 00 09 14 fe 03 13 08 11 08 2c 07}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AXVA_2147942923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AXVA!MTB"
        threat_id = "2147942923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 09 0b 04 03 07 5d 9a 28 ?? 00 00 0a 02 28 ?? 00 00 06 28 ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {03 07 03 07 91 07 04 28 ?? 00 00 06 9c 07 17 d6 0b 07 06 31 eb}  //weight: 2, accuracy: Low
        $x_2_3 = {02 03 66 5f 02 66 03 5f 60 8c ?? 00 00 01 0a 2b 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZKV_2147943021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZKV!MTB"
        threat_id = "2147943021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 13 04 11 04 45 07 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00 1b 00 00 00 40 00 00 00 1b 00 00 00 51 00 00 00 28 ?? 01 00 0a 0b 07 74 34 00 00 01 14 fe 03 0c 08 2c 05 19 13 04 2b c5 1c 2b f9 07 74 34 00 00 01 7e 6c 00 00 04 6f 3b 01 00 0a 07 75 34 00 00 01 7e 6c 00 00 04 6f ?? 01 00 0a 1a 13 04 2b 9d}  //weight: 5, accuracy: Low
        $x_4_2 = {02 7b 83 00 00 04 6f ?? 01 00 0a 0a 06 75 37 00 00 01 2a}  //weight: 4, accuracy: Low
        $x_3_3 = {02 03 16 03 8e 69 6f ?? 01 00 0a 02 6f ?? 01 00 0a 1a 0b 2b d1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ABWA_2147943044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ABWA!MTB"
        threat_id = "2147943044"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 74 ?? 00 00 01 14 fe 03 13 07 11 07 2c 05 1a 13 11 2b a5 17 2b f9 11 04 74 ?? 00 00 01 08 75 ?? 00 00 1b 6f ?? 00 00 0a 11 04 74 ?? 00 00 01 08 75 ?? 00 00 1b 6f ?? 00 00 0a 16 13 11 38 ?? ff ff ff 11 04 75 ?? 00 00 01 6f ?? 00 00 0a 13 08 73 ?? 00 00 0a 13 05 11 05 74 ?? 00 00 01 11 08 74 ?? 00 00 01 17 73 ?? 00 00 0a 13 06 1c 13 11 38 ?? ff ff ff 11 06 14 16}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZLT_2147943465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZLT!MTB"
        threat_id = "2147943465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 14 72 c3 47 00 70 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 28 3e 00 00 0a 13 05 11 04 11 05 28 60 01 00 0a 6f ?? 01 00 0a 00 11 0c 11 0b 12 0c 28 ?? 01 00 0a 13 0e 11 0e 2d c4 11 04 6f ?? 01 00 0a 0b 2b 00 07 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ANWA_2147943788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ANWA!MTB"
        threat_id = "2147943788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 05 11 05 11 04 1f 20 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 04 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 05 6f ?? 01 00 0a 11 05 6f ?? 01 00 0a 6f ?? 01 00 0a 13 06 00 73 ?? 00 00 0a 13 07 00 11 07 11 06 17 73 ?? 01 00 0a 13 09 11 09 02 16 02 8e 69 6f ?? 01 00 0a 00 11 09 6f ?? 01 00 0a 00 de 0e}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ELM_2147943938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ELM!MTB"
        threat_id = "2147943938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "InjectionHostIndex" ascii //weight: 2
        $x_1_2 = "get_AntiSandBoxie" ascii //weight: 1
        $x_1_3 = "get_AntiVM" ascii //weight: 1
        $x_1_4 = "get_StartupPersistence" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_GGZ_2147944053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.GGZ!MTB"
        threat_id = "2147944053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 1b 5d 2c 03 03 2b 07 03 20 ee 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
        $x_4_2 = {2b 16 7e 56 00 00 04 fe 06 ab 00 00 06 73 7c 00 00 0a 25 80 57 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 00 7e 58 00 00 04 2c 07 7e 58 00 00 04 2b 16 7e 56 00 00 04 fe 06 ac 00 00 06 73 7f 00 00 0a 25 80 58 00 00 04 0d 72 75 11 00 70 28 ?? 00 00 0a 13 04 11 04 14 fe 01 13 06 11 06 2c 0b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AHXA_2147944419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AHXA!MTB"
        threat_id = "2147944419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1b 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? ?? 00 0a 1b 13 11 2b af 11 09 74 ?? 00 00 01 6f ?? ?? 00 0a 11 08 75 ?? 00 00 01 6f ?? ?? 00 0a 0d de 49}  //weight: 4, accuracy: Low
        $x_2_2 = {0a 11 04 75 ?? 00 00 01 20 80 00 00 00 6f ?? ?? 00 0a 1b 13 0d 2b 85 11 04 75 ?? 00 00 01 19 6f ?? ?? 00 0a 11 04 75 ?? 00 00 01 08 74 ?? 00 00 1b 6f ?? ?? 00 0a 18 13 0d 38 ?? ff ff ff 11 04 74 ?? 00 00 01 08 74 ?? 00 00 1b 6f ?? ?? 00 0a 11 04 74 ?? 00 00 01 6f ?? ?? 00 0a 13 06 19 13 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_FZD_2147944791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.FZD!MTB"
        threat_id = "2147944791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 07 14 fe 03 0c 08 2c 7d 07 7e 4b 00 00 04 7e 4d 00 00 04 2c 07 7e 4d 00 00 04 2b 16 7e 4c 00 00 04 fe 06 74 00 00 06 73 ce 00 00 0a 25 80 4d 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 6f d1 00 00 0a 00 07 7e 4b 00 00 04 7e 4e 00 00 04 2c 07 7e 4e 00 00 04 2b 16}  //weight: 5, accuracy: Low
        $x_4_2 = {2b 16 7e 4c 00 00 04 fe 06 75 00 00 06 73 ce 00 00 0a 25 80 4e 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 00 07 19 6f ?? 00 00 0a 00 00 00 07 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AB_2147944999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AB!MTB"
        threat_id = "2147944999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 13 0b 00 73 47 01 00 0a 13 16 00 11 16 17 73 48 01 00 0a 13 18 11 18 11 0b 16 11 0b 8e 69 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZUS_2147945272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZUS!MTB"
        threat_id = "2147945272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {04 1f 09 5d 2c 03 03 2b 07 03 20 f1 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 6, accuracy: High
        $x_5_2 = {7a 00 06 7e ?? 00 00 04 2c 07 7e ?? 00 00 04 2b 16 7e ?? 00 00 04 fe 06 69 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_HZZ_2147945476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.HZZ!MTB"
        threat_id = "2147945476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 14 fe 03 13 04 11 04 39 82 00 00 00 09 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 07 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 19 6f ?? 00 00 0a 00 00 02 73 67 00 00 0a 13 05 00 11 05 09 6f ?? 00 00 0a 16 73 00 01 00 0a 13 06 00 11 06 73 01 01 00 0a 13 07 11 07 02 8e 69 6f 02 01 00 0a 0c de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_HQZ_2147945662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.HQZ!MTB"
        threat_id = "2147945662"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 1f 18 8c 63 00 00 01 6f ?? 00 00 0a 00 06 73 c0 00 00 0a 6f ?? 00 00 0a 00 16 0b 09 06 16 6f ?? 00 00 0a 14 72 12 4f 0c 70 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 17 8c 63 00 00 01 28 76 00 00 0a 16 8c 63 00 00 01 15 8c 63 00 00 01 12 02 12 03 28 ?? 00 00 0a 13 04 11 04 39 a6 01 00 00 06 18 6f ?? 00 00 0a 74 0c 00 00 1b 06 16 6f ?? 00 00 0a 74 0a 00 00 1b 09 28 79 00 00 0a 91 6f ?? 00 00 0a 00 07 17 5d 16 fe 01 13 05 11 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MOZ_2147946117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MOZ!MTB"
        threat_id = "2147946117"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 1e 5d 2c 03 03 2b 07 03 20 e2 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
        $x_4_2 = {11 06 17 d6 13 06 11 08 14 17 8d 03 00 00 01 25 16 07 a2 6f ?? 00 00 0a 28 ?? 00 00 0a 13 09 11 09 74 43 00 00 01 13 0a 11 0a 6f ?? 00 00 0a 1f 18 9a 13 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AMZA_2147946262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AMZA!MTB"
        threat_id = "2147946262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 06 11 06 11 04 6f ?? 01 00 0a 00 11 06 11 05 6f ?? 01 00 0a 00 11 06 11 06 6f ?? 01 00 0a 11 06 6f ?? 01 00 0a 6f ?? 01 00 0a 13 07 00 73 ?? 00 00 0a 13 08 00 11 08 11 07 17 73 ?? 01 00 0a 13 09 11 09 02 16 02 8e 69 6f ?? 01 00 0a 00 11 09 6f ?? 01 00 0a 00 11 08 6f ?? 00 00 0a 0a de 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_SL_2147946432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.SL!MTB"
        threat_id = "2147946432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 0c 11 0e 11 0c 6c 11 0e 6c 28 06 01 00 0a 11 0c 11 0e d6 17 d6 6c 5b 28 07 01 00 0a 11 0e 17 d6 13 0e 11 0e 11 0d 31 d5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MSZ_2147946973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MSZ!MTB"
        threat_id = "2147946973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 09 0b 04 03 07 5d 9a 28 ?? 01 00 0a 02 28 ?? 00 00 06 28 ?? 01 00 0a 0a 2b 00 06 2a}  //weight: 5, accuracy: Low
        $x_4_2 = {02 03 66 5f 02 66 03 5f 60 8c 66 00 00 01 0a 2b 00 06}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZBT_2147947145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZBT!MTB"
        threat_id = "2147947145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {04 1e 5d 2c 03 03 2b 07 03 20 db 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 6, accuracy: High
        $x_5_2 = {11 05 17 d6 13 05 11 07 14 72 26 09 01 70 18 8d ?? 00 00 01 25 17 17 8d ?? 00 00 01 25 16 07 a2 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 08 11 08 74 ?? 00 00 01 13 09 11 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_TQD_2147947495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.TQD!MTB"
        threat_id = "2147947495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 06 2b 28 11 06 6f ?? 01 00 0a 28 ?? 00 00 0a 13 07 07 11 07 28 ?? 00 00 0a 03 28 ?? 01 00 06 b4 6f ?? 01 00 0a 00 08 17 d6 0c 00 11 06 6f ?? 01 00 0a 13 08 11 08 2d cb}  //weight: 5, accuracy: Low
        $x_4_2 = {02 03 61 0b 07 0a 2b 00 06 2a}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AUBB_2147948599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AUBB!MTB"
        threat_id = "2147948599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 09 73 ?? 01 00 0a 13 04 73 ?? 01 00 0a 25 11 04 1f 20 6f ?? 01 00 0a 6f ?? 01 00 0a 00 25 11 04 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 13 05 11 05 6f ?? 01 00 0a 13 06 02 73 ?? 01 00 0a 13 07 11 07 11 06 16 73 ?? 01 00 0a 13 08 02 8e 69 17 da 17 d6 8d ?? 00 00 01 13 09 11 08 11 09 16 11 09 8e 69 6f ?? 01 00 0a 13 0a 11 0a 17 da 17 d6 8d ?? 00 00 01 13 0b 11 09 11 0b 11 0a 28 ?? 01 00 0a 00 11 0b 0a de 51}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_MCA_2147948710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.MCA!MTB"
        threat_id = "2147948710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 06 72 b8 12 00 70 7d 76 00 00 04 16 06 7b 76 00 00 04 6f ?? 00 00 0a 6c 23 00 00 00 00 00 00 00 40 5b 28 ec 00 00 0a b7 28 ?? 01 00 0a 06 fe 06 16 01 00 06 73 33 01 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0d 08 09 20 e8 03 00 00 73 34 01 00 0a 13 04 00 73 35 01 00 0a 13 05 11 05 11 04 1f 20 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 04 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 05 11 05 6f ?? 01 00 0a 11 05 6f ?? 01 00 0a 6f 3b 01 00 0a 13 06 00 73 3c 01 00 0a 13 07 00 11 07 11 06 17 73 3d 01 00 0a 13 09 11 09 02 16 02 8e 69 6f ?? 01 00 0a 00 11 09 6f ?? 01 00 0a 00 de 0e 00 11 09 2c 08 11 09 6f ?? 00 00 0a 00 dc 11 07 13 08 11 08 0b de 1c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_NNA_2147948832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.NNA!MTB"
        threat_id = "2147948832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 75 68 00 00 01 09 74 67 00 00 01 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 75 68 00 00 01 09 75 67 00 00 01 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 1a 13 0c 2b aa}  //weight: 5, accuracy: Low
        $x_4_2 = {11 05 75 69 00 00 01 02 74 0b 00 00 1b 16 02 14 20 6f fc 34 00 1d 21 08 00 00 00 00 00 00 00 14 28 ?? 02 00 06 16 8d 06 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 13 06 18}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_EEV_2147949221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.EEV!MTB"
        threat_id = "2147949221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 08 1a 5d 16 fe 01 13 09 11 09 2c 0f 02 11 08 02 11 08 91 20 c4 00 00 00 61 b4 9c 11 08 17 d6 13 08 11 08 11 07 31 d8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_EFV_2147949328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.EFV!MTB"
        threat_id = "2147949328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 17 11 07 16 9a 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 02 00 0a 00 74 da 00 00 01 0c 08 07 6f ?? 02 00 0a 00 07 6f ?? 02 00 0a 0d 09 73 a7 02 00 0a 13 04 00 28 ?? 02 00 0a 13 09 11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 7e b9 01 00 04 2c 07 7e b9 01 00 04 2b 16 7e b8 01 00 04 fe 06 76 03 00 06 73 ac 02 00 0a 25 80 b9 01 00 04 13 0a 00 11 09 6f ?? 02 00 0a 13 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ASCB_2147949345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ASCB!MTB"
        threat_id = "2147949345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 13 05 11 05 6f ?? ?? 00 0a 13 06 73 ?? ?? 00 0a 13 07 11 07 11 06 17 73 ?? ?? 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? ?? 00 0a 00 11 08 6f ?? ?? 00 0a 00 11 07 6f ?? ?? 00 0a 0a de 45}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_HHY_2147949426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.HHY!MTB"
        threat_id = "2147949426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 1c 5d 2c 03 03 2b 07 03 20 cb 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
        $x_4_2 = {02 7e 1b 01 00 04 2c 07 7e 1b 01 00 04 2b 16 7e 1a 01 00 04 fe 06 8e 02 00 06 73 5c 01 00 0a 25 80 1b 01 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_PGDT_2147949542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.PGDT!MTB"
        threat_id = "2147949542"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 0a 13 05 11 05 17 1f 14 6f ?? ?? 00 0a 13 04 2b 26 11 04 1f 0a fe 02 13 06 11 06 2c 0c 07 08 66 5f 07 66 08 5f 60 0d 2b 13 00 11 05 17 1f 14 6f ?? ?? 00 0a 13 04 00 17 13 07 2b d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_KTS_2147949636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.KTS!MTB"
        threat_id = "2147949636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {18 13 0a 11 0a 45 07 00 00 00 00 00 00 00 4e 00 00 00 00 00 00 00 42 00 00 00 42 00 00 00 25 00 00 00 25 00 00 00 07 74 88 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 07 75 88 00 00 01 20 80 00 00 00 6f ?? 00 00 0a 1c 13 0a 2b b8 07 74 88 00 00 01 19 6f ?? 00 00 0a 07 75 88 00 00 01 03 6f 8f 00 00 0a 19 13 0a 2b 9b 07 75 88 00 00 01 03 6f ?? 00 00 0a 07 75 88 00 00 01 6f ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BRB_2147949701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BRB!MTB"
        threat_id = "2147949701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 06 14 a2 11 06 17 d6 13 06 11 06 11 05 31 ef 72 bf 2c 00 70 28 ?? 01 00 0a 0d 08 06 7b f9 01 00 04 17 da 09}  //weight: 4, accuracy: Low
        $x_5_2 = {06 0b 00 73 60 01 00 0a 0c 00 08 07 28 ?? 00 00 06 0d 09 02 28 ?? 00 00 06 00 08 6f ?? 01 00 0a 0a de 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BIB_2147949972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BIB!MTB"
        threat_id = "2147949972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 14 fe 01 0c 08 2c 0b 72 d2 77 00 70 73 01 02 00 0a 7a 00 06 7e 02 01 00 04 2c 07 7e 02 01 00 04 2b 16 7e 01 01 00 04 fe 06 3a 02 00 06 73 02 02 00 0a 25 80 02 01 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0b}  //weight: 4, accuracy: Low
        $x_5_2 = {04 1e 5d 2c 03 03 2b 07 03 20 cf 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ALEB_2147951297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ALEB!MTB"
        threat_id = "2147951297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 0a 11 0a 06 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 0a 06 6f ?? 01 00 0a 6f ?? 01 00 0a 00 7e ?? 01 00 04 2c 07 7e ?? 01 00 04 2b 16 7e ?? 01 00 04 fe ?? ?? ?? 00 06 73 ?? 01 00 0a 25 80 ?? 01 00 04 13 0b 00 11 0a 6f ?? 01 00 0a 13 0c 02 11 0b 08 6f ?? 01 00 0a 11 0c 6f ?? 01 00 0a 6f ?? 00 00 0a 00 de 0e}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AREB_2147951581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AREB!MTB"
        threat_id = "2147951581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 07 07 11 07 28 ?? ?? 00 0a 03 28 ?? ?? 00 06 b4 6f ?? ?? 00 0a 00 00 11 06 6f ?? ?? 00 0a 13 08 11 08 2d cf}  //weight: 5, accuracy: Low
        $x_2_2 = {02 03 61 0b 07 0a 2b 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_FPZ_2147951970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.FPZ!MTB"
        threat_id = "2147951970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 06 14 17 8d 03 00 00 01 25 16 07 a2 6f ?? 01 00 0a 14 72 ce 3c 00 70 17 8d 03 00 00 01 25 16 1f 18 8c a7 00 00 01 a2 14 14 14 28 ?? 01 00 0a 14 72 e0 3c 00 70 16}  //weight: 4, accuracy: Low
        $x_5_2 = {04 17 5d 2c 03 03 2b 04 03 1f 60 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AUEB_2147952050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AUEB!MTB"
        threat_id = "2147952050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 17 5d 2c 03 03 2b 04 03 1f 48 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
        $x_2_2 = {0a 0a 06 14 72 ?? ?? 00 70 17 8d ?? 00 00 01 25 16 28 ?? ?? 00 06 28 ?? 00 00 2b 28 ?? 00 00 2b 7e ?? ?? 00 04 2c 07 7e ?? ?? 00 04 2b 16 7e ?? ?? 00 04 fe ?? ?? ?? 00 06 73 ?? ?? 00 0a 25 80 ?? ?? 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b a2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZVO_2147952135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZVO!MTB"
        threat_id = "2147952135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {04 17 5d 2c 03 03 2b 04 03 1f 66 61 b4 0a 2b 00 06 2a}  //weight: 6, accuracy: High
        $x_4_2 = {01 25 16 28 ?? 01 00 06 28 ?? 00 00 2b 28 ?? 00 00 2b 7e 10 01 00 04 2c 07 7e 10 01 00 04 2b 16 7e 0d 01 00 04 fe 06 15 02 00 06 73 c1 02 00 0a 25 80 10 01 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b a2 14}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_KRI_2147952341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.KRI!MTB"
        threat_id = "2147952341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 14 72 dc d4 00 70 17 8d 03 00 00 01 25 16 28 ?? 02 00 06 28 ?? 00 00 2b 28 ?? 00 00 2b 7e 19 00 00 04 2c 07 7e 19 00 00 04 2b 16 7e 18 00 00 04 fe 06 93 00 00 06 73 c1 00 00 0a 25 80 19 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b}  //weight: 4, accuracy: Low
        $x_5_2 = {04 18 5d 2c 03 03 2b 07 03 20 c1 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BAI_2147952417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BAI!MTB"
        threat_id = "2147952417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 16 7e 18 00 00 04 fe 06 93 00 00 06 73 c1 00 00 0a 25 80 19 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b a2 14 14 14 28 ?? 00 00 0a 14 72 f6 d4 00 70 17 8d 03 00 00 01 25 16 1f 18 8c 6f 00 00 01 a2 14 14 14}  //weight: 4, accuracy: Low
        $x_5_2 = {04 18 5d 2c 03 03 2b 07 03 20 c1 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BPI_2147952532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BPI!MTB"
        threat_id = "2147952532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 09 1f 20 6f ?? 01 00 0a 6f ?? 01 00 0a 00 11 04 09 1f 10 6f ?? 01 00 0a 6f ?? 01 00 0a 00 00 11 04 6f ?? 01 00 0a 13 05 11 05 02 74 26 00 00 1b 16 02 14 72 53 30 00 70 16 8d 01 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 01 00 0a 13 06 11 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AOFB_2147952723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AOFB!MTB"
        threat_id = "2147952723"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 17 5d 2c 03 03 2b 04 03 1f ?? 61 b4 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
        $x_2_2 = {13 07 11 07 11 04 6f ?? ?? 00 0a b7 6f ?? ?? 00 0a 13 08 11 08 28 ?? ?? 00 0a 00 11 08 0b de 39}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BRR_2147953004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BRR!MTB"
        threat_id = "2147953004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2c 07 7e 19 00 00 04 2b 16 7e 18 00 00 04 fe 06 93 00 00 06 73 c1 00 00 0a 25 80 19 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b a2 14 14 14}  //weight: 4, accuracy: Low
        $x_5_2 = {04 18 5d 2c 03 03 2b 07 03 20 c1 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZZN_2147953754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZZN!MTB"
        threat_id = "2147953754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {03 08 02 03 08 91 08 04 28 ?? 01 00 06 9c 08 17 d6 0c 08 07 31 ea 03 0a 2b 00 06 2a}  //weight: 6, accuracy: Low
        $x_4_2 = {1f 09 0b 05 04 07 5d 9a 28 ?? 00 00 0a 0c 03 0d 08 09 60 08 66 09 66 60 5f b4 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BRC_2147954539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BRC!MTB"
        threat_id = "2147954539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2c 07 7e 98 01 00 04 2b 16 7e 97 01 00 04 fe 06 4f 03 00 06 73 e0 02 00 0a 25 80 98 01 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b a2 14 14 14 28 ?? 01 00 0a 14}  //weight: 4, accuracy: Low
        $x_5_2 = {04 1a 5d 2c 03 03 2b 07 03 20 f3 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_BRT_2147955016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.BRT!MTB"
        threat_id = "2147955016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 00 73 0b 02 00 0a 0c 00 08 07 28 ?? 03 00 06 0d 09 02 28 ?? 03 00 06 00 08 6f ?? 01 00 0a 0a de 24 00 09 2c 07 09 6f ?? 00 00 0a 00 dc}  //weight: 5, accuracy: Low
        $x_4_2 = {0b 07 14 fe 03 0c 08 2c 7d 07 7e e8 01 00 04 7e f8 01 00 04 2c 07 7e f8 01 00 04 2b 16 7e f6 01 00 04 fe 06 c5 03 00 06 73 76 02 00 0a 25 80 f8 01 00 04}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZXM_2147955293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZXM!MTB"
        threat_id = "2147955293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {04 0a 16 0b 2b 11 02 07 02 07 91 07 03 28 ?? 02 00 06 9c 07 17 d6 0b 07 06 31 eb}  //weight: 6, accuracy: Low
        $x_4_2 = {1f 09 0b 04 03 07 5d 9a 28 ?? 02 00 0a 02 28 ?? 02 00 06 28 ?? 02 00 0a 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
        $x_2_3 = {02 03 66 5f 02 66 03 5f 60 8c ?? 00 00 01 0a 2b 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZCL_2147955501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZCL!MTB"
        threat_id = "2147955501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 06 11 05 06 11 05 91 20 d3 00 00 00 61 9c 00 00 11 05 17 d6 13 05 11 05 11 04 31 d7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZOM_2147956116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZOM!MTB"
        threat_id = "2147956116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 09 1f 09 5d 16 fe 01 13 0a 11 0a 2c 11 11 04 11 09 11 04 11 09 91 20 f3 00 00 00 61 9c 00 00 11 09 17 d6 13 09 11 09 11 08 31 d4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZNA_2147956200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZNA!MTB"
        threat_id = "2147956200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1f 09 0b 04 03 07 5d 9a 28 ?? 01 00 0a 02 28 ?? 01 00 06 28 ?? 01 00 0a 0a 2b 00 06 2a}  //weight: 4, accuracy: Low
        $x_5_2 = {02 03 66 5f 02 66 03 5f 60 8c 90 00 00 01 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZFF_2147956361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZFF!MTB"
        threat_id = "2147956361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 06 1b 5d 16 fe 01 13 07 11 07 2c 0f 07 11 06 07 11 06 91 20 a9 00 00 00 61 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AOJB_2147956613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AOJB!MTB"
        threat_id = "2147956613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 03 1f 10 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 07 07 6f ?? ?? 00 0a 07 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0c 00 73 ?? ?? 00 0a 0d 00 09 08 17 ?? ?? 01 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? ?? 00 0a 00 11 05 6f ?? ?? 00 0a 00 de 0e}  //weight: 5, accuracy: Low
        $x_2_2 = {02 03 1b da 16 8d ?? 00 00 01 a2 02 03 1d da 02 03 1c da 9a 74 ?? 00 00 01 6f ?? ?? 00 0a 02 8e 69 20 00 01 00 00 5d 9a a2 02 8e 69 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AYJB_2147956862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AYJB!MTB"
        threat_id = "2147956862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 06 1c 5b 1c d8 da 16 fe 01 13 09 11 09 2c 0d 02 06 02 06 91 20 b2 00 00 00 61 9c 00 00 06 17 d6 0a 00 06 07 fe 04 13 0a 11 0a 2d d3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_FRI_2147957233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.FRI!MTB"
        threat_id = "2147957233"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 72 71 1c 00 70 17 8d 04 00 00 01 25 16 28 ?? 03 00 06 28 ?? 00 00 2b 28 ?? 00 00 2b 7e c3 00 00 04 2c 07 7e c3 00 00 04 2b 16 7e bf 00 00 04 fe 06 4c 02 00 06 73 0c 01 00 0a 25 80 c3 00 00 04}  //weight: 4, accuracy: Low
        $x_5_2 = {04 1e 5d 2c 03 03 2b 07 03 20 a4 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ABLB_2147957590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ABLB!MTB"
        threat_id = "2147957590"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 14 fe 01 0c 08 2c 04 14 0a de 50 28 ?? 00 00 0a 20 39 30 00 00 61 0b 02 75 ?? 00 00 1b 14 fe 03 0d 09 2c 22 02 74 ?? 00 00 1b 13 04 11 04 8e 69 1f 40 fe 02 13 05 11 05 2c 0a 11 04 28 ?? 00 00 0a 0a de 17 00 00 00 de 0d 28 ?? 00 00 0a 00 28 ?? 00 00 0a de 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_GRI_2147957811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.GRI!MTB"
        threat_id = "2147957811"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2c 07 7e d0 02 00 04 2b 16 7e ce 02 00 04 fe 06 2e 04 00 06 73 27 03 00 0a 25 80 d0 02 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 14 0c 14 0d 14 13 04 14 13 05 00 28 ?? 03 00 0a 0d 09 14 fe 03 13 06 11 06 2c 1f 09 07 28 ?? 04 00 06 00 09 6f ?? 03 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? 03 00 0a 0a de 21}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZAI_2147957882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZAI!MTB"
        threat_id = "2147957882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 14 fe 01 0c 08 2c 04 14 0a de 50 28 ?? 01 00 0a 20 39 30 00 00 61 0b 02 75 ?? 00 00 1b 14 fe 03 0d 09 2c 22 02 74 ?? 00 00 1b 13 04 11 04 8e}  //weight: 5, accuracy: Low
        $x_5_2 = {02 03 17 da 9a 14 fe 01 13 07 11 07 2c 05 dd 01 01 00 00 02 03 17 da 9a 28 ?? 00 00 0a 28 ?? 02 00 06 0b 07 14 fe 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZLJ_2147958404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZLJ!MTB"
        threat_id = "2147958404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 8e 69 17 da 0b 16 0c 2b 11 02 08 02 08 91 20 ec 00 00 00 61 b4 9c 08 1e d6 0c 08 07 31 eb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_PGDA_2147958415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.PGDA!MTB"
        threat_id = "2147958415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 09 2c 06 72 ?? 76 00 70 0a 1f 64 28 ?? 00 00 0a 00 1f 1a 28 ?? ?? 00 0a 72 ?? 76 00 70 28 ?? ?? 00 0a 0b 73 72 01 00 06 0c 08 28 ?? ?? 00 0a 00 de 17}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_AJMB_2147958585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.AJMB!MTB"
        threat_id = "2147958585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 19 5d 16 fe 01 13 05 11 05 2c 12 07 11 04 02 11 04 91 20 b8 00 00 00 61 b4 9c 00 2b 0a 00 07 11 04 02 11 04 91 9c 00 11 04 17 d6 13 04 11 04 09 31 cc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZYJ_2147959000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZYJ!MTB"
        threat_id = "2147959000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {04 0a 16 0b 2b 11 02 07 02 07 91 07 03 28 ?? 01 00 06 9c 07 17 d6 0b 07 06 31 eb 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkTortilla_ZZJ_2147959092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkTortilla.ZZJ!MTB"
        threat_id = "2147959092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkTortilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 05 6f ?? 02 00 0a 11 05 6f ?? 02 00 0a 6f ?? 02 00 0a 13 06 00 73 ?? 01 00 0a 13 07 00 11 07 11 06 17 73 ?? 02 00 0a 13 09 11 09 02 16 02 8e 69 6f ?? 02 00 0a 00 11 09 6f ?? 02 00 0a 00 de 0e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

