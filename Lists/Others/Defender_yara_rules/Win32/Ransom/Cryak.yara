rule Ransom_Win32_Cryak_PA_2147750928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cryak.PA!MTB"
        threat_id = "2147750928"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cryak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "how_to_decrypt.hta" wide //weight: 1
        $x_1_2 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "DELETE BACKUP -keepVersions:0" ascii //weight: 1
        $x_1_4 = "/set {default} recoveryenabled No" ascii //weight: 1
        $x_1_5 = "All your documents, databases, backups and other important files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

