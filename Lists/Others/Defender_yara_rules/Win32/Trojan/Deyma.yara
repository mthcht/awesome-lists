rule Trojan_Win32_Deyma_DSK_2147744951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deyma.DSK!MTB"
        threat_id = "2147744951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b c0 09 a3 ?? ?? ?? ?? 8b 85 2c fe ff ff 40 89 85 2c fe ff ff 8b 85 44 fe ff ff 33 05 ?? ?? ?? ?? 89 85 44 fe ff ff 8b 85 e4 fe ff ff b9 2c 01 00 00 ff e0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deyma_ME_2147812923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deyma.ME!MTB"
        threat_id = "2147812923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f8 8b 11 8b 45 f8 8b 48 08 8a 14 11 88 55 ff}  //weight: 5, accuracy: High
        $x_5_2 = {55 8b ec 83 ec 08 89 4d fc 8b 45 fc 89 45 f8 6b 45 08 18 8b 4d f8 03 01 8b e5 5d c2 04 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deyma_MBHK_2147852138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deyma.MBHK!MTB"
        threat_id = "2147852138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 24 89 2d ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 ce 33 c1 2b f8 8b d7 c1 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {54 00 4e 00 65 00 7a 00 6f 00 76 00 69 00 64 00 61 00 66 00 69 00 77 00 69 00 20 00 67 00 6f 00 7a 00 61 00 67 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deyma_MBJZ_2147893343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deyma.MBJZ!MTB"
        threat_id = "2147893343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 33 db 33 d8 80 07 ?? 33 c6 8b f3 8b c6 8b c0 8b f3 8b db 33 d8 33 c3 33 c6 f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
        $x_1_2 = "vdwxfythdrnramdpevwcxqtdglktg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deyma_MBJZ_2147893343_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deyma.MBJZ!MTB"
        threat_id = "2147893343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qvdwxfythdrnramdpevwcxqtdglktgxy" ascii //weight: 1
        $x_1_2 = "tiwoybllpanpecizpodtzbdbfjyobhkqndjwkayahxvlfflfakswhxlrohrybyxkjzlytjjsnfexfdiffbxhnp" ascii //weight: 1
        $x_1_3 = "iferpbjgyujqbltcthoqqwfmfnwsrulusnnfucvlrkezmxxkqwimmtxtxlclphjojlsovwmujhlmayqvhxufkmwn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Deyma_ARA_2147899010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deyma.ARA!MTB"
        threat_id = "2147899010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deyma"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 34 30 41 40 3b c1 72 f7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

