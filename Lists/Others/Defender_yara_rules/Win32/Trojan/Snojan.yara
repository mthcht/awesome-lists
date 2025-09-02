rule Trojan_Win32_Snojan_AJS_2147842670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snojan.AJS!MTB"
        threat_id = "2147842670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 fe 10 8d 8d 98 91 ff ff 0f 43 c8 8a 07 83 c7 02 88 04 0b 8b 9d a8 91 ff ff 43 89 9d a8 91 ff ff 3b fa 74 0e 8b b5 ac 91 ff ff 8b 85 98 91 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Snojan_ASFQ_2147905956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snojan.ASFQ!MTB"
        threat_id = "2147905956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wecan.hasthe.technology/upload" ascii //weight: 1
        $x_1_2 = "ma au ga rre gyaje weel" ascii //weight: 1
        $x_1_3 = "rifaien2-%s.exe" ascii //weight: 1
        $x_1_4 = "ma num wa rifaien yanje" ascii //weight: 1
        $x_1_5 = "ma num wa gyen orn hyzik %s en exec ween NODE%i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Snojan_ERTG_2147951134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snojan.ERTG!MTB"
        threat_id = "2147951134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snojan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5a 88 02 ff 07 4b ?? ?? 33 c0 5a 59 59 64 89 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

