rule Trojan_MSIL_BazarLoader_AC_2147798146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BazarLoader.AC!MTB"
        threat_id = "2147798146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {13 02 20 06 00 00 00 38 5e ff ff ff 11 01 11 04 1f 7f 5f 1d 11 03 5a 1c 58 1f 1f 5f 62 60 13 01 38 a9 ff ff ff 11 01 66 2a 11 01 2a 16 13 00}  //weight: 10, accuracy: High
        $x_3_2 = "SecurityFix.Properties" ascii //weight: 3
        $x_3_3 = "Pledtorg" ascii //weight: 3
        $x_3_4 = "System.Security.Cryptography.AesCryptoServiceProvider" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_BazarLoader_RPF_2147811602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/BazarLoader.RPF!MTB"
        threat_id = "2147811602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Affichage" wide //weight: 1
        $x_1_2 = "quitterToolStripMenuItem" wide //weight: 1
        $x_1_3 = "scientifiqueToolStripMenuItem" wide //weight: 1
        $x_1_4 = "aideToolStripMenuItem" wide //weight: 1
        $x_1_5 = "RazerInstaller" wide //weight: 1
        $x_1_6 = "Calculatrice" wide //weight: 1
        $x_1_7 = "CreateInstance" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

