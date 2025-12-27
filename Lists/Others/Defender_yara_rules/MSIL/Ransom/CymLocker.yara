rule Ransom_MSIL_CymLocker_NRA_2147958761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/CymLocker.NRA!MTB"
        threat_id = "2147958761"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CymLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Please enter the path to encrypt" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "Your personal files are encrypted!" ascii //weight: 1
        $x_2_4 = "ransomware\\Bytelocker-master\\Bytelocker\\obj\\Debug\\CymLocker.pdb" ascii //weight: 2
        $x_1_5 = "Decrypting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

