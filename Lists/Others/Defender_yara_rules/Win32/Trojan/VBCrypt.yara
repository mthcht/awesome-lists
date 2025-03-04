rule Trojan_Win32_VBcrypt_WSG_2147787697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBcrypt.WSG!MTB"
        threat_id = "2147787697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Demiurges1" ascii //weight: 1
        $x_1_2 = "Callosities3" ascii //weight: 1
        $x_1_3 = "Accretionary" ascii //weight: 1
        $x_1_4 = "Blandishment" ascii //weight: 1
        $x_1_5 = "elwjnzlhigka" wide //weight: 1
        $x_1_6 = "dkzzioxgu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBcrypt_EPQ_2147787777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBcrypt.EPQ!MTB"
        threat_id = "2147787777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBcrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "slievovitserne" ascii //weight: 1
        $x_1_2 = "VILDSKAB" ascii //weight: 1
        $x_1_3 = "Hosier" ascii //weight: 1
        $x_1_4 = "tidsglose" ascii //weight: 1
        $x_1_5 = "Forhandlingsgrundlagene" ascii //weight: 1
        $x_1_6 = "TELEFONKDERNE" ascii //weight: 1
        $x_1_7 = "Honoraries3" ascii //weight: 1
        $x_1_8 = "Saplings" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

