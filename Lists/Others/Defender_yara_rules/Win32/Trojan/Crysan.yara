rule Trojan_Win32_Crysan_SIBC_2147813070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysan.SIBC!MTB"
        threat_id = "2147813070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 00 00 00 00 8a 8b ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 74 ?? f6 d1 80 c1 ?? 80 f1 ?? 80 c1 ?? 80 f1 ?? 88 8b 00 83 c3 01 8a 8b 00 81 fb 01 66 59 5b 8d 45 ?? 50 6a 40 68 01 68 00 ff 15 ?? ?? ?? ?? 6a 00 68 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crysan_RK_2147906821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysan.RK!MTB"
        threat_id = "2147906821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0d 98 ee 69 00 56 57 bf 4e e6 40 bb e8 cd 1d e3 ff 3b cf 74 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crysan_AMMF_2147907582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysan.AMMF!MTB"
        threat_id = "2147907582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 33 ca 0f af 4d dc 89 8d ?? ?? ?? ?? 52 50 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crysan_EAZK_2147936810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crysan.EAZK!MTB"
        threat_id = "2147936810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 f8 01 d0 31 cb 89 da 88 10 83 45 f8 01 8b 45 f8 3b 45 18 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

