rule Trojan_Win32_LotusLite_AB_2147962677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LotusLite.AB!MTB"
        threat_id = "2147962677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LotusLite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "172.81.60.97" ascii //weight: 6
        $x_6_2 = "Global\\Technology360-A@P@T-Team" ascii //weight: 6
        $x_4_3 = "DataImporterMain" ascii //weight: 4
        $x_4_4 = "kugou.dll" ascii //weight: 4
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "KugouMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LotusLite_GXI_2147967540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LotusLite.GXI!MTB"
        threat_id = "2147967540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LotusLite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f8 83 c4 08 85 ff ?? ?? 8b 3d ?? ?? ?? ?? 6a 3c ff d7 4e 85 f6}  //weight: 10, accuracy: Low
        $x_1_2 = "\\ProgramData\\Microsoft_DNX" ascii //weight: 1
        $x_1_3 = "\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "goldenjackel12" ascii //weight: 1
        $x_1_5 = "editor.gleeze.com" wide //weight: 1
        $x_1_6 = "KugouMain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LotusLite_RH_2147968070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LotusLite.RH!MTB"
        threat_id = "2147968070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LotusLite"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 21 0b 01 0e 00}  //weight: 2, accuracy: Low
        $x_2_2 = "goldenjackel12" ascii //weight: 2
        $x_1_3 = "Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "HDFCBankMain" ascii //weight: 1
        $x_1_5 = "Evt1Query" ascii //weight: 1
        $x_1_6 = "Hi,First Time" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

