rule Ransom_Win32_Mole_PA_2147745537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mole.PA!MTB"
        threat_id = "2147745537"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mole"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attention! All Your data was encrypted!" ascii //weight: 1
        $x_1_2 = "DECRYPT-ID-%s number" ascii //weight: 1
        $x_1_3 = "%s\\_HELP_INSTRUCTION.TXT" wide //weight: 1
        $x_1_4 = "aaa_TouchMeNot_.txt" wide //weight: 1
        $x_1_5 = ".FILE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mole_YAB_2147852141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mole.YAB!MTB"
        threat_id = "2147852141"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mole"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--BEGIN PUBLIC KEY--" ascii //weight: 1
        $x_1_2 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_3 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_4 = "_HELP_INSTRUCTION.TXT" wide //weight: 1
        $x_1_5 = "All of your files are encrypted" wide //weight: 1
        $x_1_6 = "Your DECRYPT-ID" wide //weight: 1
        $x_1_7 = ".MOLE02" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Mole_DA_2147891321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Mole.DA!MTB"
        threat_id = "2147891321"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Mole"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 8b 4d f0 03 02 31 4d d8 33 02 50 8f 03 83 c2 04 0f b6 c1 8b c1 0b 05 ?? ?? ?? ?? 47 8b c7 89 7d e0 8b 7d 18 2b c7 8b 7d e0 75 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 81 e9 52 15 48 10 8b 0d ?? ?? ?? ?? 03 35 ?? ?? ?? ?? f7 5d d8 83 c3 04 49 0f 85 06 00 89 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

