rule Trojan_MSIL_Bobik_ABIS_2147838868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.ABIS!MTB"
        threat_id = "2147838868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 9a 6f ?? ?? ?? 0a 0c 12 02 28 ?? ?? ?? 0a 0a 06 73 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 16 16 16 16 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 02 03 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "ScreenShoter.Properties" ascii //weight: 1
        $x_1_3 = "ScreenShoter.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NEAA_2147838960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NEAA!MTB"
        threat_id = "2147838960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "e1497e3c-6e45-466e-83f7-bbff4b534c7a" ascii //weight: 7
        $x_5_2 = "aspnet_wp.exe" wide //weight: 5
        $x_2_3 = "AutoIt v3 ActiveX Control" ascii //weight: 2
        $x_2_4 = "Powered by SmartAssembly 7.2.0.2789" ascii //weight: 2
        $x_2_5 = "Jonathan Bennett & AutoIt Team" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NEAB_2147840114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NEAB!MTB"
        threat_id = "2147840114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$229ec2cd-f6b0-4ca7-a93b-0ade87858d62" ascii //weight: 5
        $x_5_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 5
        $x_2_3 = "m9OIO8Q0EK" ascii //weight: 2
        $x_2_4 = "pZbnhv6YB" ascii //weight: 2
        $x_2_5 = "C356AFF1A01C2B0DA47" ascii //weight: 2
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NBV_2147841234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NBV!MTB"
        threat_id = "2147841234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 09 9a 28 15 00 00 0a 8e 2c 02 17 0b 09 17 58 0d 09 06 8e 69 32 e9}  //weight: 5, accuracy: High
        $x_1_2 = "splatshot.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NBK_2147841598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NBK!MTB"
        threat_id = "2147841598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 e8 01 00 0a 58 28 ?? ?? 00 0a 61 69 61 69 fe ?? ?? 00 61 5e}  //weight: 5, accuracy: Low
        $x_1_2 = "N Spoofer" ascii //weight: 1
        $x_1_3 = "Neox Spoofer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NBK_2147841598_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NBK!MTB"
        threat_id = "2147841598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 0a 7e ?? 00 00 04 28 ?? 00 00 06 00 28 ?? 00 00 0a 14 fe ?? ?? ?? ?? 06 73 ?? 00 00 0a 6f ?? 00 00 0a 00 06 7e ?? 00 00 04 28 ?? 00 00 06 00 28 ?? 00 00 0a 6f ?? 00 00 0a 26}  //weight: 5, accuracy: Low
        $x_1_2 = "wwcd.exe" ascii //weight: 1
        $x_1_3 = "Windows\\Win.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NKB_2147843408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NKB!MTB"
        threat_id = "2147843408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 49 00 00 70 28 ?? ?? 00 0a 0a 06 0b 72 ?? ?? 00 70 07 28 ?? ?? 00 0a 28 ?? ?? 00 0a 26 73 ?? ?? 00 0a 0c 08 72 ?? ?? 00 70 72 ?? ?? 00 70 73 ?? ?? 00 0a 6f ?? ?? 00 0a 00 07 6f ?? ?? 00 0a 18 fe 02 16 fe 01 0d 09 2d 1f 00 08 72 ?? ?? 00 70 07 28 ?? ?? 00 0a 72 ?? ?? 00 70 07 28 ?? ?? 00 0a 6f ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "guid.cmd.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_CNS_2147844655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.CNS!MTB"
        threat_id = "2147844655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 00 00 fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? 61 d1 6f ?? ?? ?? ?? 26 fe ?? ?? ?? 20 ?? ?? ?? ?? 58 fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? ?? 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PSIQ_2147844983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PSIQ!MTB"
        threat_id = "2147844983"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 2b 00 00 02 7e 51 01 00 04 28 86 03 00 06 7e 5c 01 00 04 28 b2 03 00 06 72 8c 04 00 70 7e 7a 01 00 04 28 ea 03 00 06 73 2a 00 00 0a 25 7e 61 01 00 04 28 c2 03 00 06 16 6a 7e 62 01 00 04 28 c6 03 00 06 25 25 7e 61 01 00 04 28 c2 03 00 06 7e 76 01 00 04 28 de 03 00 06 69 7e 7b 01 00 04 28 ee 03 00 06 0a 7e 39 01 00 04 28 32 03 00 06 06 28 a4 00 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PSMO_2147846446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PSMO!MTB"
        threat_id = "2147846446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 16 13 04 07 8e 69 28 46 00 00 0a 13 05 02 7b 05 00 00 04 11 05 6f 47 00 00 0a 26 2b 1c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_ABK_2147849689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.ABK!MTB"
        threat_id = "2147849689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 06 11 05 11 04 08 09 73 0c 00 00 06 a2 7e 09 00 00 04 07 9a 6f ?? ?? ?? 0a 7e 09 00 00 04 07 9a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 06}  //weight: 1, accuracy: Low
        $x_1_2 = {0c 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 06 0d 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 06 13 07 12 07 28 ?? ?? ?? 0a 13 04 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 06 13 07 12 07 28 ?? ?? ?? 0a 13 05 08 09 20 0b 20 0e 00 73 3a 00 00 0a 13 06 11 06 28 ?? ?? ?? 0a 13 08 11 08 11 05 11 04 16 16 11 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_AAEE_2147850208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.AAEE!MTB"
        threat_id = "2147850208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 2d 20 7e ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 6f ?? 00 00 0a 73 ?? 00 00 0a 0a 06 80 ?? 00 00 04 7e ?? 00 00 04 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "DataEvoSoft.Res1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_AAFL_2147850725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.AAFL!MTB"
        threat_id = "2147850725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 0a 03 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 0c 08 28 ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 07 73 ?? 00 00 0a 13 04 11 04 09 16 73 ?? 00 00 0a 13 05 11 05 73 ?? 00 00 0a 13 06 11 06 6f ?? 00 00 0a 13 07 de 2e 11 06 2c 07 11 06 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "4151c432-ef52-4939-91ad-b87c5df82633" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_GNC_2147851472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.GNC!MTB"
        threat_id = "2147851472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ot devas dna nekat tohsneercS" ascii //weight: 1
        $x_1_2 = "detelpmoc yllufsseccus releduhcs ksat ot putrats ot gniypoC" ascii //weight: 1
        $x_1_3 = "W9yZ2xhY29sIHRlbiAmICMjIyNwdW9yRyBsYWNvTCMjIy" ascii //weight: 1
        $x_1_4 = "BlbWFucmVkaXZvcnAsbm9pdHBpcm" ascii //weight: 1
        $x_1_5 = "Exela.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_ABI_2147851587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.ABI!MTB"
        threat_id = "2147851587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 09 18 72 43 01 00 70 a2 09 19 28 ?? ?? ?? 0a a2 09 1a 72 6f 01 00 70 a2 09 1b 08 16 9a 6f ?? ?? ?? 0a a2 09 1c 72 7f 01 00 70 a2 09 1d 28 ?? ?? ?? 0a a2 09 1e 72 9b 01 00 70 a2 09 1f 09 28 ?? ?? ?? 0a a2 09 1f 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PSTQ_2147851953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PSTQ!MTB"
        threat_id = "2147851953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 19 00 00 0a 0a 06 28 ?? 00 00 0a 0b 07 16 16 16 16 06 6f ?? 00 00 0a 6f ?? 00 00 0a 00 06 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 72 01 00 00 70 28 ?? 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_AAJC_2147852485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.AAJC!MTB"
        threat_id = "2147852485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 03 28 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 08 73 ?? 00 00 0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 05 11 05 73 ?? 00 00 0a 13 06 11 06 6f ?? 00 00 0a 13 07 de 0a 26}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "WF_Doc.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_GMD_2147888123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.GMD!MTB"
        threat_id = "2147888123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hcijkcl" ascii //weight: 1
        $x_1_2 = "mcncocqjsjujxwz" ascii //weight: 1
        $x_1_3 = "api.telegram.org/bot5083760279:AAHDfrHveB72fisr6bMz4JQZjmspQIgzyXY/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_ARA_2147892029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.ARA!MTB"
        threat_id = "2147892029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Olimpoks10.pdb" ascii //weight: 2
        $x_2_2 = "C:\\System\\filescreenshot" ascii //weight: 2
        $x_2_3 = "Login" ascii //weight: 2
        $x_2_4 = "Password" ascii //weight: 2
        $x_2_5 = "Userneme/id" ascii //weight: 2
        $x_2_6 = "DexVin" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NNB_2147892299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NNB!MTB"
        threat_id = "2147892299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 4c 00 00 0a 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 1f 28 da 73 ?? 00 00 0a 16 16 73 ?? 00 00 0a 11 06 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Taskbar Destroyer.exe" ascii //weight: 1
        $x_1_3 = "WinForms_RecursiveFormCreate" wide //weight: 1
        $x_1_4 = "WinForms_SeeInnerException" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PTAZ_2147895523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PTAZ!MTB"
        threat_id = "2147895523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 1f 00 00 0a 03 28 ?? 00 00 0a 13 05 11 05 2c 10 00 02 11 04 09 28 ?? 00 00 06 00 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PTBJ_2147895670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PTBJ!MTB"
        threat_id = "2147895670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 1c 00 00 0a 0b 12 01 28 ?? 00 00 0a 73 1f 00 00 0a 0a 06 28 ?? 00 00 0a 0c 00 08 16 16 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_AAJW_2147896760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.AAJW!MTB"
        threat_id = "2147896760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Run Malware?" wide //weight: 1
        $x_1_2 = "Are you sure?" wide //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "DisableRegistryTools" wide //weight: 1
        $x_1_5 = "Shell_TrayWnd" wide //weight: 1
        $x_1_6 = "cmd.exe" wide //weight: 1
        $x_1_7 = "Tera_Bonus.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PTCA_2147896767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PTCA!MTB"
        threat_id = "2147896767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 16 12 00 28 ?? 00 00 0a 6f 44 00 00 0a 7e 08 00 00 04 72 48 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 6f 46 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PTCD_2147896858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PTCD!MTB"
        threat_id = "2147896858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 2c 00 00 0a 0b 00 07 0c 16 0d 38 e6 00 00 00 08 09 9a 13 04 00 72 a6 03 00 70 11 04 28 ?? 00 00 0a 28 ?? 00 00 06 00 11 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_AB_2147897792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.AB!MTB"
        threat_id = "2147897792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 0a 06 2c 17 00 03 04 28 17 00 00 0a 28 29 00 00 0a 6f 2a 00 00 0a 00 17 0b 2b 04 16 0b 2b 00 07 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PSIJ_2147899374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PSIJ!MTB"
        threat_id = "2147899374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 1d 28 43 00 00 0a 0b 28 ?? ?? ?? 0a 0c 07 72 21 00 00 70 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 fe 01 0d 09 2c 19 08 07 72 21 00 00 70 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 00 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PSKV_2147899409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PSKV!MTB"
        threat_id = "2147899409"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 07 28 0f 00 00 0a 11 07 6f ?? ?? ?? 0a 13 08 11 06 11 08 16 11 08 8e 69 6f ?? ?? ?? 0a 1b 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 09 a2 25 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PTER_2147900244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PTER!MTB"
        threat_id = "2147900244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 1e 00 00 0a 28 ?? 00 00 0a 6f 19 00 00 0a 0b 12 01 28 ?? 00 00 0a 6f 20 00 00 0a 00 00 de 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_PTFJ_2147900533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.PTFJ!MTB"
        threat_id = "2147900533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 06 16 07 6f 8b 01 00 0a 02 06 16 06 8e 69 6f 8c 01 00 0a 25 0b 16 30 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_AMMA_2147903731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.AMMA!MTB"
        threat_id = "2147903731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 11 d2 13 31 11 11 1e 63 d1 13 11 11 1b 11 09 91 13 20 11 1b 11 09 11 20 11 23 61 11 1e 19 58 61 11 31 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_NB_2147914403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.NB!MTB"
        threat_id = "2147914403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 17 94 59 11 04 16 94 59 9e}  //weight: 2, accuracy: High
        $x_2_2 = {11 04 18 94 59 11 04 17 94 59 11 04 16 94}  //weight: 2, accuracy: High
        $x_1_3 = "Client.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_SAV_2147931432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.SAV!MTB"
        threat_id = "2147931432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 16 6a 6f 24 00 00 0a 72 ?? ?? ?? 70 0c 73 25 00 00 0a 13 05 73 26 00 00 0a 13 06 11 06 06 73 27 00 00 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f 28 00 00 0a 73 29 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Bobik_GMT_2147961632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Bobik.GMT!MTB"
        threat_id = "2147961632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AAH2UWtHaUU0i_3OmxK7mzmRLTK8MfsWzSk" ascii //weight: 1
        $x_1_2 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp1.pdb" ascii //weight: 1
        $x_1_4 = "TelegramWorker" ascii //weight: 1
        $x_1_5 = "SendToTelegram" ascii //weight: 1
        $x_1_6 = "/sendDocument" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

