rule Trojan_Win32_AresLdr_LK_2147845745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AresLdr.LK!MTB"
        threat_id = "2147845745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AresLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "AresLdr_" ascii //weight: 10
        $x_5_2 = {68 74 74 70 3a 2f 2f [0-240] 2f 70 61 79 6c 6f 61 64}  //weight: 5, accuracy: Low
        $x_5_3 = {68 74 74 70 3a 2f 2f [0-240] 2f 6c 65 67 69 74}  //weight: 5, accuracy: Low
        $x_1_4 = {67 65 6f 5c [0-5] 3a 20 27 25 73 27 2c 20 5c [0-5] 73 65 72 76 69 63 65 5c [0-5] 3a 20 27 25 73 27 2c 20 5c [0-5] 6f 77 6e 65 72 5f 74 6f 6b 65 6e}  //weight: 1, accuracy: Low
        $x_1_5 = "tzutil /g" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_AresLdr_MK_2147846513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AresLdr.MK!MTB"
        threat_id = "2147846513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AresLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 ff 8b bd ?? ?? ?? ?? 8d 04 0e 8d 04 41 01 c8 2b 15 ?? ?? ?? ?? 01 c2 01 f2 01 ca 01 ca 01 d6 8b 95 ?? ?? ?? ?? 01 ce 01 f1 8b 35 ?? ?? ?? ?? 8a 84 0e ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 32 04 1a 43 88 04 39 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

