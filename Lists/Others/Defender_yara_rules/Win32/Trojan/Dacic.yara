rule Trojan_Win32_Dacic_AD_2147891732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.AD!MTB"
        threat_id = "2147891732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2a c1 8a ca c0 e9 04 c0 e3 02 83 c4 20 0a cb 8a 5c 24 1c 46 47 80 fb 40 75 ?? 8b 44 24 24 32 db 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_ADC_2147898765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.ADC!MTB"
        threat_id = "2147898765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 c7 04 24 d8 85 40 00 58 e8 ?? ?? ?? ?? 4f 31 01 81 c6 ?? ?? ?? ?? 41 29 ff 39 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_HNA_2147908590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.HNA!MTB"
        threat_id = "2147908590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vhmhmds-ckk" ascii //weight: 1
        $x_1_2 = "Kn`cKhaq`qx@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_NA_2147908646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.NA!MTB"
        threat_id = "2147908646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {01 d8 31 d8 c1 e0 03 c1 eb 02 90 80 2f 88 f6 2f 47 e2 de}  //weight: 10, accuracy: High
        $x_5_2 = "_crypted.dll" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_AMAA_2147909871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.AMAA!MTB"
        threat_id = "2147909871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 41 0d f7 6d fc 03 45 10 51 b9 11 00 00 00 33 d2 f7 f1 59 33 d2 f7 75 f0 8a 04 16 88 03 41 43 3b f9 7f}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 6a 00 e8 ?? ?? ?? 00 e8 ?? ?? ?? 00 3d b7 00 00 00 74 ?? e8 ?? ?? ?? ff 54 6a 00 6a 00 68 ?? ?? ?? 00 6a 00 6a 00 e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_KAB_2147912862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.KAB!MTB"
        threat_id = "2147912862"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Software\\Tdgus Avodw Public\\TjboApp" ascii //weight: 5
        $x_1_2 = "libsocvbi86a.dll" ascii //weight: 1
        $x_1_3 = "conncn.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_LIL_2147913203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.LIL!MTB"
        threat_id = "2147913203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 8a 14 19 32 d3 8d 04 19 8a 8d a8 fe ff ff 32 d1 8d 8d 94 fe ff ff 88 10 8d 95 20 fe ff ff c7 85 28 ?? ?? ?? 10 94 40 00 89 bd 20 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_ARAZ_2147928951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.ARAZ!MTB"
        threat_id = "2147928951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 14 c5 00 00 00 00 2b d0 03 d2 2b ca 8a 81 ?? ?? ?? ?? 88 44 1e ff 3b f7 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_PGC_2147939894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.PGC!MTB"
        threat_id = "2147939894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c5 89 45 fc 57 8d 85 f0 ee ff ff 50 68 00 10 00 00 8d 8d f8 ee ff ff 33 ff 51 89 bd f4 ee ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {43 3a 5c 48 57 49 44 2e 74 78 74 00 43 3a 5c 00 0d 2b 32 22 3a 27 2f 3f 03 3d 2b 21 07 71 34 32 3d 39 33 33 70 31 13 35 28 38 2c 31 05 15 4b 59 44}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dacic_MBZ_2147941591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dacic.MBZ!MTB"
        threat_id = "2147941591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 3b 40 00 b0 18 40 00 7f f2 30 01 00 ff ff ff 08 00 00 00 01 00 00 00 03 00 01 00 e9 00 00 00 50 14 40 00 90 16 40 00 e8 11 40 00 78 00 00 00 83 00 00 00 8c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

