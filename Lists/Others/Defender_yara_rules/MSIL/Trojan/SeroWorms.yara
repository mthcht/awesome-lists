rule Trojan_MSIL_SeroWorms_BA_2147970476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SeroWorms.BA!MTB"
        threat_id = "2147970476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SeroWorms"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SeroLocker" ascii //weight: 1
        $x_1_2 = "BCryptEncrypt" ascii //weight: 1
        $x_1_3 = "RansomWarePayload.pdb" ascii //weight: 1
        $x_1_4 = ".crypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

