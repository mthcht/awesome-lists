rule Trojan_Win32_CymRan_ACR_2147895859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CymRan.ACR!MTB"
        threat_id = "2147895859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 55 fc 52 8b 45 10 03 45 fc 50 8b 4d 0c 03 4d fc 51 8b 55 08 52 ff 15 f4 90 43 00 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CymRan_M_2147895877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CymRan.M!MTB"
        threat_id = "2147895877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CymulateNativeRansomwareGeneratedKey" ascii //weight: 1
        $x_1_2 = "programdata\\Cymulate" ascii //weight: 1
        $x_1_3 = "EncryptedFiles" ascii //weight: 1
        $x_1_4 = "EDR_attacks_path" ascii //weight: 1
        $x_1_5 = "AttacksLogs\\edr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CymRan_A_2147909471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CymRan.A!MTB"
        threat_id = "2147909471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 0c 1a 8b c2 8b 5d ?? 83 e0 ?? 42 8a 84 30 ?? ?? ?? ?? 32 04 0b 8b 5d ?? 88 01 3b d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CymRan_B_2147909718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CymRan.B!MTB"
        threat_id = "2147909718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CymRan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b ce f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8d 0c 40 8b c6 c1 e1}  //weight: 2, accuracy: Low
        $x_2_2 = "attack_id" ascii //weight: 2
        $x_2_3 = "EDR_attacks_path" ascii //weight: 2
        $x_2_4 = "cnc_url" ascii //weight: 2
        $x_2_5 = "cnc_email" ascii //weight: 2
        $x_2_6 = "cnc_connection_token" ascii //weight: 2
        $x_2_7 = "new_file_server_mode" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

