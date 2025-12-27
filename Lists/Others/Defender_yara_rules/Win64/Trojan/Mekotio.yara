rule Trojan_Win64_Mekotio_MCH_2147928189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mekotio.MCH!MTB"
        threat_id = "2147928189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mekotio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UVw8YCmZ9vntF9Bt5GhH/-rT6jBCOAXech5H5OiuW" ascii //weight: 1
        $x_1_2 = "Injectmoduleconseito" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Mekotio_GVA_2147958998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Mekotio.GVA!MTB"
        threat_id = "2147958998"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Mekotio"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 9b 02 19 61 0d 12 44 b2 b4 bd c6 4f 03 15 16 5f ef e3 db 5f 5c 5d 14 16 55 8e 90 b1 ff b6 36 fe 7d 26 9a 9c b5 02 1c 69 f2 9d 64 0d 12 32 17}  //weight: 2, accuracy: High
        $x_1_2 = {54 78 da ec 9d 09 40 94 65 fe c7 7f 30 30 0c 73 70 8c c3 35 0c 30 0c 20 24 97 02 21 66 87 68 6a db 66 fd db dc ca b2 c3 0e 2d d7 4a 37 a3 b6 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

