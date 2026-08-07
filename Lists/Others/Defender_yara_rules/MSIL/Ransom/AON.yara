rule Ransom_MSIL_AON_AOR_2147975397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/AON.AOR!MTB"
        threat_id = "2147975397"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AON"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kingofmoney1@protonmail.com" ascii //weight: 1
        $x_1_2 = "AON Ransomware" ascii //weight: 1
        $x_1_3 = "What happened to my computer" ascii //weight: 1
        $x_1_4 = "Your important files have been encrypted" ascii //weight: 1
        $x_1_5 = "Many of your documents, photos, videos, databases and other files are no longer accessible because they have been encrypted" ascii //weight: 1
        $x_1_6 = "Can I recover my files" ascii //weight: 1
        $x_1_7 = "We guarantee that you can recover all your files safely and easily" ascii //weight: 1
        $x_1_8 = "aon_backup" ascii //weight: 1
        $x_1_9 = "aonenc" ascii //weight: 1
        $x_1_10 = "NoaCrypter.exe enum -B -S" ascii //weight: 1
        $x_1_11 = "NoaCrypter.exe persist -E <PATH>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

