rule TrojanSpy_MSIL_Bobik_BIK_2147831378_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bobik.BIK!MTB"
        threat_id = "2147831378"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 92 03 00 70 0a 06 28 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 08 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "freegeoip.app/xml" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Bobik_AFMM_2147837450_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bobik.AFMM!MTB"
        threat_id = "2147837450"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 0a 06 09 16 11 04 6f 24 00 00 0a 08 09 16 09 8e 69 6f 31 00 00 0a 25 13 04 16 30 e5}  //weight: 2, accuracy: High
        $x_1_2 = "Install.Resource" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Bobik_AB_2147838186_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bobik.AB!MTB"
        threat_id = "2147838186"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 1d 06 02 07 6f ?? ?? ?? 0a 03 61 d1 0c 12 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 04 0d 09 2d d6}  //weight: 2, accuracy: Low
        $x_1_2 = "GetCurrentDirectory" ascii //weight: 1
        $x_1_3 = "GetFiles" ascii //weight: 1
        $x_1_4 = "GetFlag" ascii //weight: 1
        $x_1_5 = "Ts'mBUGzUsnk'oCsd'jds|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Bobik_ABK_2147895579_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bobik.ABK!MTB"
        threat_id = "2147895579"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 04 00 11 04 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 00 de 0d 11 04 2c 08 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 12 00 28 ?? 00 00 0a 12 00 28 ?? 00 00 0a 73 2c 00 00 0a 0b 07 28 ?? 00 00 0a 0c 00 08 7e 2e 00 00 0a 7e 2e 00 00 0a 12 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Bobik_SK_2147901751_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bobik.SK!MTB"
        threat_id = "2147901751"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 08 16 08 8e 69 6f 33 00 00 0a 13 05 28 34 00 00 0a 11 05 6f 35 00 00 0a 13 06 de 0c}  //weight: 2, accuracy: High
        $x_2_2 = "\\resourcefilehaha.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Bobik_PADT_2147904993_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Bobik.PADT!MTB"
        threat_id = "2147904993"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bobik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c3.yarttdn.de" wide //weight: 1
        $x_1_2 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup\\Asmpl.lnk" wide //weight: 1
        $x_1_3 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\\\powershell.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

