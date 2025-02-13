rule Ransom_MSIL_HoneyLocker_PA_2147900341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HoneyLocker.PA!MTB"
        threat_id = "2147900341"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HoneyLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Honey" wide //weight: 1
        $x_1_2 = "Your files, videos, documents, and other important data have been encrypted." ascii //weight: 1
        $x_1_3 = "WARNING! if you restart computer to your file is can't recovery forever!" ascii //weight: 1
        $x_1_4 = "\\HoneyLocker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

