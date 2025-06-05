rule TrojanDownloader_MSIL_XWorm_CXIT_2147848490_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/XWorm.CXIT!MTB"
        threat_id = "2147848490"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 72 01 00 00 70 28 0e 00 00 06 13 00 38 0f 00 00 00 02 11 01 28 0d 00 00 06 13 02 38 18 00 00 00 28 03 00 00 0a 11 00 6f ?? ?? ?? ?? 28 05 00 00 0a 13 01}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 63 00 61 00 74 00 62 00 6f 00 78 00 2e 00 6d 00 6f 00 65 00 2f [0-31] 00 70 00 6e 00 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_XWorm_OKA_2147920555_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/XWorm.OKA!MTB"
        threat_id = "2147920555"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "obj\\Debug\\Bootstrapper1488.pdb" ascii //weight: 1
        $x_1_2 = "https://s715sas.storage.yandex.net" ascii //weight: 1
        $x_1_3 = "limit=0&content_type=application%2Fx-dosexec&owner_uid=1891002355&fsize=62464" ascii //weight: 1
        $x_1_4 = "Loader.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_XWorm_SFD_2147942896_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/XWorm.SFD!MTB"
        threat_id = "2147942896"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Copying shellcode failed" ascii //weight: 2
        $x_1_2 = "amsi.exe" ascii //weight: 1
        $x_1_3 = "x_64.txt" ascii //weight: 1
        $x_1_4 = "Shortcut created at" ascii //weight: 1
        $x_1_5 = "Task created successfully" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

