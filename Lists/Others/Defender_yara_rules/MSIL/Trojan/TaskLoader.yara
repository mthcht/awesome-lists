rule Trojan_MSIL_taskloader_NBL_2147896414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/taskloader.NBL!MTB"
        threat_id = "2147896414"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "taskloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 10 00 1e 64 61 fe 0e 10 00 fe 0c 10 00 fe 0c 02 00 58 fe 0e 10 00 fe 0c 10 00 fe 0c 10 00 1f 17 64 61 fe 0e 10 00 fe 0c 10 00 fe 0c 2e 00 58 fe 0e 10 00 fe 0c 10 00 fe 0c 10 00 1f 09 62 61 fe 0e 10 00 fe 0c 10 00 fe 0c 32 00 58 fe 0e 10 00 fe 0c 23 00 1b 62 fe 0c 02 00 58 fe 0c 02 00 61 fe 0c 10 00 59 fe 0e 10 00 fe 0c 10 00}  //weight: 1, accuracy: High
        $x_1_2 = "EncryptSimpleString" ascii //weight: 1
        $x_1_3 = "DecryptSimpleString" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "BeginInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

