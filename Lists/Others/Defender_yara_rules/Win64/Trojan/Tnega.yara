rule Trojan_Win64_Tnega_SG_2147893384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tnega.SG!MSR"
        threat_id = "2147893384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ogd368hc.dll" ascii //weight: 1
        $x_1_2 = "IBEZd59E" ascii //weight: 1
        $x_1_3 = "2Glorious %s Investigate+ %d@ estate( Pig Declared('Confession) angel intervention$ wolves " ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "FindFirstFileA" ascii //weight: 1
        $x_1_6 = "FindNextFileA" ascii //weight: 1
        $x_1_7 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tnega_AC_2147896088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tnega.AC!MTB"
        threat_id = "2147896088"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 c6 00 00 00 e9 72 01 00 00 4d 31 0e e9 cb 00 00 00 e9 11 01}  //weight: 10, accuracy: High
        $x_10_2 = {4d 6b c9 00 eb 04 eb d8 eb 2a 4d 69 c9 2f df eb 5a eb 69}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tnega_GTM_2147896102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tnega.GTM!MTB"
        threat_id = "2147896102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 57 08 48 8b ce 48 87 ff 81 f2 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 85 c0 4d 87 f6 0f 84 2e 02 00 00 49 33 c6 48 ff c3 4d 89 db 48 93 48 89 1f 48 93 48 83 c7 ?? 4d 89 e4 48 83 fb ?? 0f 82 bf ff ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Tnega_DA_2147924484_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Tnega.DA!MTB"
        threat_id = "2147924484"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Tnega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "wmiccomputersystemgetmodelFailed" ascii //weight: 10
        $x_1_2 = "aes_encrypt" ascii //weight: 1
        $x_10_3 = "powershellClear-EventLog" ascii //weight: 10
        $x_1_4 = "Encrypted:" ascii //weight: 1
        $x_1_5 = "VirtualBox" ascii //weight: 1
        $x_1_6 = "VMware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

