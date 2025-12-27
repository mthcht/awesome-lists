rule Trojan_Win32_Lockbit_SRP_2147835864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockbit.SRP!MTB"
        threat_id = "2147835864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a3 fc 19 58 00 c6 05 93 24 42 00 65 c6 05 89 24 42 00 69 c6 05 8c 24 42 00 75 c6 05 8e 24 42 00 6c c6 05 8d 24 42 00 61 c6 05 91 24 42 00 6f c6 05 95 24 42 00 74 c6 05 88 24 42 00 56 c6 05 94 24 42 00 63 c6 05 8f 24 42 00 50 c6 05 96 24 42 00 00 c6 05 8b 24 42 00 74 c6 05 92 24 42 00 74 c6 05 8a 24 42 00 72 c6 05 90 24 42 00 72}  //weight: 2, accuracy: High
        $x_1_2 = "sel.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lockbit_RPZ_2147848973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockbit.RPZ!MTB"
        threat_id = "2147848973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c3 c1 e0 04 89 44 24 14 83 f9 05}  //weight: 1, accuracy: High
        $x_1_2 = {8d 34 2b 89 44 24 14 8b c3 c1 e8 05 89 44 24 10 83 f9 1b}  //weight: 1, accuracy: High
        $x_1_3 = {8b d7 c1 e2 04 89 54 24 14 8b 44 24 24 01 44 24 14 8b c7 c1 e8 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lockbit_MBFA_2147896783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockbit.MBFA!MTB"
        threat_id = "2147896783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "joxoramakamamihudovuj" ascii //weight: 1
        $x_1_2 = "nucusimokadocorixehoga" ascii //weight: 1
        $x_1_3 = "xopazalujico sesolemugihamegiroxeced tohakemodexexucibekuxed korusahiwetofevexadopeneborivube" ascii //weight: 1
        $x_1_4 = "perikivutegosucizugeg" ascii //weight: 1
        $x_1_5 = "hekenowatemabapapajiwiwenafo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lockbit_MBFV_2147903392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockbit.MBFV!MTB"
        threat_id = "2147903392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 dc 89 45 f8 8b 45 e4 31 45 fc 8b 45 fc 33 45 f8 81 45 f0 ?? ?? ?? ?? 2b f0 ff 4d e0 89 45 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {72 b5 33 db a1 ?? ?? ?? ?? 03 c3 3d 8d 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lockbit_AB_2147952697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lockbit.AB!MTB"
        threat_id = "2147952697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 c7 c1 c0 07 33 f0 8b 44 24 28 03 c6 89 74 24 38 c1 c0 09 31 44 24 20 8b 44 24 20 03 c6 8b 74 24 34 c1 c0 0d 33 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

