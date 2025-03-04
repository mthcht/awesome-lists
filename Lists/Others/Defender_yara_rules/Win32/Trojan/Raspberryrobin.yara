rule Trojan_Win32_Raspberryrobin_CI_2147851197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raspberryrobin.CI!MTB"
        threat_id = "2147851197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raspberryrobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DtrcytvJinm" ascii //weight: 2
        $x_2_2 = "EexrctDrctvy" ascii //weight: 2
        $x_2_3 = "DxerctSxrctvy" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raspberryrobin_AA_2147851199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raspberryrobin.AA!MTB"
        threat_id = "2147851199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raspberryrobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c0 83 c6 01 8a 46 ff 32 02 56 83 c4 04 88 07 47 89 c0 42 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 52 83 c4 04 83 e9 01 68 ?? ?? ?? ?? 83 c4 04 85 c9 80 3a 00 68 ?? ?? ?? ?? 83 c4 04 8b 55 14}  //weight: 1, accuracy: Low
        $x_1_2 = {89 c0 83 c6 01 8a 46 ff 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 89 c0 32 02 90 aa 56 83 c4 04 83 c2 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 68 ?? ?? ?? ?? 83 c4 04 85 c9 80 3a 00 53 83 c4 04 8b 55 14 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_3 = {56 83 c4 04 8a 06 83 c6 01 90 57 83 c4 04 32 02 47 88 47 ff 83 c2 01 68 ?? ?? ?? ?? 83 c4 04 68 ?? ?? ?? ?? 83 c4 04 49 85 c9 80 3a 00 8b 55 14}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 06 83 c6 01 68 ?? ?? ?? ?? 83 c4 04 32 02 83 c7 01 88 47 ff 56 83 c4 04 42 89 c0 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9 80 3a 00 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 8b 55 14 68 ?? ?? ?? ?? 83 c4 04}  //weight: 1, accuracy: Low
        $x_1_5 = {89 c0 46 8a 46 ff 90 89 c0 32 02 aa 89 c0 89 c0 83 c2 01 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 85 c9 75}  //weight: 1, accuracy: Low
        $x_1_6 = {8a 06 46 89 c0 53 83 c4 04 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 aa 42 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 49 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Raspberryrobin_RA_2147851206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raspberryrobin.RA!MTB"
        threat_id = "2147851206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raspberryrobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IniubyGtrrrrcr" ascii //weight: 1
        $x_1_2 = "PoiinFxrct" ascii //weight: 1
        $x_1_3 = "LnfuhTvtcr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raspberryrobin_RB_2147851207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raspberryrobin.RB!MTB"
        threat_id = "2147851207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raspberryrobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RxdtcyOinub" ascii //weight: 1
        $x_1_2 = "SrerrttrtHunim" ascii //weight: 1
        $x_1_3 = "OinufGcrtvyb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raspberryrobin_RC_2147851208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raspberryrobin.RC!MTB"
        threat_id = "2147851208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raspberryrobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c0 ac 32 02 83 ec 04 c7 04 24 ?? ?? ?? ?? 83 c4 04 88 07 83 c7 01 56 83 c4 04 42 50 83 c4 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Raspberryrobin_DA_2147851260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raspberryrobin.DA!MTB"
        threat_id = "2147851260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raspberryrobin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UbfggvFrtvyb" ascii //weight: 1
        $x_1_2 = "tdhyfjgy.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

