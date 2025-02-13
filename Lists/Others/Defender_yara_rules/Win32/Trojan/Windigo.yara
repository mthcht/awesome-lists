rule Trojan_Win32_Windigo_DSK_2147741879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.DSK!MTB"
        threat_id = "2147741879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 f4 8b 08 03 ca 8a 51 03 8a da 8a c2 80 e2 f0 c0 e0 06 0a 41 02 80 e3 fc c0 e2 02 0a 11 c0 e3 04 0a 59 01 8d 4d f8 88 14 3e 88 5c 3e 01}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Windigo_MB_2147842390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.MB!MTB"
        threat_id = "2147842390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "G4pjLWL7p39oSqrCo" ascii //weight: 5
        $x_5_2 = "O-FU/GnS2HHOU_ywWV9XgE6_(u52_" ascii //weight: 5
        $x_5_3 = "gjbYawdTjIOg2CSu/h6fakJEhJg1Kncc" ascii //weight: 5
        $x_5_4 = {62 59 61 77 64 54 6a 49 4f 67 32 43 53 75 2f 68 36 66 61 6b 4a 45 68 4a 67 31 4b 6e 63 63 9b}  //weight: 5, accuracy: High
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "UPX0" ascii //weight: 1
        $x_1_7 = "UPX1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Windigo_MA_2147842622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.MA!MTB"
        threat_id = "2147842622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "EuzB3KipGssabBo8" ascii //weight: 5
        $x_5_2 = "vzy7WyS6Xo1cUz9PXm/56G0xEo9u" ascii //weight: 5
        $x_5_3 = {ff 35 fb 05 0f 86 90 05 10 86 64 6e 6c 8b 4c 24 68 85 eb de 3e fb c0 0f 84 e1 03 24 86 18 89 1e}  //weight: 5, accuracy: High
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "UPX0" ascii //weight: 1
        $x_1_6 = "UPX1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Windigo_MC_2147844001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.MC!MTB"
        threat_id = "2147844001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "nFSwz0JjJavZlTaEH8sr" ascii //weight: 5
        $x_5_2 = "/QeLQn-lGQPVeHV4_VRHq/cBAKuuwBDpU9TFlbzy1s" ascii //weight: 5
        $x_5_3 = "/2zmg7xqj1u2F-D0RJqZE" ascii //weight: 5
        $x_5_4 = {b4 bf 9e 76 d0 03 9f 76 5a 53 9f 76 27 19 9e 76 c0 50 9d 76 65 de 9e 76 42 f1 9e 76 e3 10 a3 76 cc 8d a0 76 b2 de 9e 76 d7 96 9e 76 1f 91 9f 76}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Windigo_GMK_2147891523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.GMK!MTB"
        threat_id = "2147891523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 e8 8b 4d ?? 03 cf 03 d3 03 45 ?? 81 c3 ?? ?? ?? ?? 33 c1 33 c2 29 45 ?? ff 4d ?? 89 45 ?? 0f 85 ?? ?? ?? ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Windigo_AMMC_2147905000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.AMMC!MTB"
        threat_id = "2147905000"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "p://expertcarriage.site/arra.php" ascii //weight: 2
        $x_2_2 = "ps://planesgold.site/tracker/thank_you.php" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Windigo_AMMD_2147905344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.AMMD!MTB"
        threat_id = "2147905344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c7 d3 e8 03 c6 89 45 ec 33 45 e4 31 45 fc 8b 45 fc 29 45 f4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Windigo_AMAE_2147910745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Windigo.AMAE!MTB"
        threat_id = "2147910745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Windigo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

