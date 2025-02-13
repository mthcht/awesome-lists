rule Trojan_MSIL_SpyStealer_AM_2147817816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyStealer.AM!MTB"
        threat_id = "2147817816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "panelss.xyz/Stealer/TSave" wide //weight: 1
        $x_1_2 = "encrypted_key" wide //weight: 1
        $x_1_3 = "vmware" wide //weight: 1
        $x_1_4 = "PK11SDR_Decrypt" wide //weight: 1
        $x_1_5 = "VirtualBox" wide //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpyStealer_FZA_2147818772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpyStealer.FZA!MTB"
        threat_id = "2147818772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 1a 00 00 04 07 7e 1a 00 00 04 07 91 20 ?? ?? ?? 00 59 d2 9c 00 07 17 58 0b 07 7e 1a 00 00 04 8e 69 fe 04 0c 08 2d d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

