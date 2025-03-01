rule Trojan_MSIL_CrimsonRAT_A_2147750227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRAT.A!MSR"
        threat_id = "2147750227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRAT"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jpg|8292" wide //weight: 1
        $x_1_2 = "Rharbwd" wide //weight: 1
        $x_1_3 = "ntharprmes" wide //weight: 1
        $x_1_4 = "dreaom.zip" wide //weight: 1
        $x_1_5 = "Debug\\verthirms.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRAT_C_2147750564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRAT.C!MSR"
        threat_id = "2147750564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRAT"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5.189.134.216" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|thnaviwa" wide //weight: 1
        $x_1_3 = "bdss=Bit Defender,onlinent=QHeal,bdagent=BD Agent,msseces=MS Essentials,fssm32=FSecure,avp=Kaspersky" ascii //weight: 1
        $x_1_4 = "Debug\\thnaviwa.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRAT_PI_2147751807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRAT.PI!MSR"
        threat_id = "2147751807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRAT"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dhrwarhsav.exe" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|dhrwarhsav" wide //weight: 1
        $x_1_3 = "$9f2eb7bb-e209-44ed-8663-78fadc78e682" ascii //weight: 1
        $x_1_4 = {5c 64 68 72 77 61 72 68 73 61 76 5c 64 68 72 77 61 72 68 73 61 76 5c 6f 62 6a 5c [0-16] 5c 64 68 72 77 61 72 68 73 61 76 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_CrimsonRAT_B_2147760052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRAT.B!MTB"
        threat_id = "2147760052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 64 73 73 [0-32] 6f 6e 6c 69 6e 65 6e 74 3d 51 [0-32] 62 64 61 67 65 6e 74 [0-32] 6d 73 73 65 63 65 73 3d 4d [0-32] 66 73 73 6d}  //weight: 1, accuracy: Low
        $x_1_2 = "DESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CrimsonRAT_MBAT_2147838921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CrimsonRAT.MBAT!MTB"
        threat_id = "2147838921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CrimsonRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 2b ca 11 06 11 05 08 6f ?? 00 00 0a 13 07 09 73 ?? 00 00 0a 13 08 11 08 11 07 16 73 ?? 00 00 0a 13 09 09 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

