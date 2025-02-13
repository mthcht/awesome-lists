rule Trojan_Win32_Bsymem_DSK_2147755332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bsymem.DSK!MTB"
        threat_id = "2147755332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d fc 03 ce 30 01 b8 01 00 00 00 29 45 fc 39 7d fc 7d 05 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bsymem_SQ_2147781659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bsymem.SQ!MTB"
        threat_id = "2147781659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunProgram=\"hidcon:cmd /c cmd < Colpo.sldx" ascii //weight: 1
        $x_1_2 = "Avra.aspx" wide //weight: 1
        $x_1_3 = "Saluta.accde" wide //weight: 1
        $x_1_4 = "Mezzo.accdr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bsymem_RF_2147788441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bsymem.RF!MTB"
        threat_id = "2147788441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 01 89 45 b4 8a 4d ec 88 4d ff 0f be 55 ff 85 d2 75 0b 8b 45 b0 89 85 bc fe ff ff eb 13 0f be 45 ff 33 45 b0 b9 93 01 00 01 f7 e1 89 45 b0 eb c3 81 bd bc fe ff ff 1b f9 d0 b3 75 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bsymem_CE_2147812745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bsymem.CE!MTB"
        threat_id = "2147812745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 12 40 3d 89 36 13 01 89 44 24 18 0f 8c}  //weight: 1, accuracy: High
        $x_1_2 = {46 81 fe 93 22 0b 18 89 1d [0-4] 7c c3}  //weight: 1, accuracy: Low
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bsymem_AO_2147833310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bsymem.AO!MTB"
        threat_id = "2147833310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bsymem"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 b8 03 45 e8 89 45 b4 8b 45 d8 03 45 b4 8b 55 ec 31 02 6a 00 e8 [0-4] 8b d8 8b 45 e8 83 c0 04 03 d8 6a 00 e8 [0-4] 2b d8 6a 00 e8 [0-4] 03 d8 6a 00 e8 [0-4] 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

