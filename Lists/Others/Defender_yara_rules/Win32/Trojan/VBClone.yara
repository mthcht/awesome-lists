rule Trojan_Win32_VBclone_CCIO_2147924724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBclone.CCIO!MTB"
        threat_id = "2147924724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBclone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c7 45 fc 03 00 00 00 c7 85 04 ff ff ff 94 30 40 00 c7 85 fc fe ff ff 08 00 00 00 8d 95 fc fe ff ff 8d 8d 2c ff ff ff ff 15}  //weight: 5, accuracy: High
        $x_1_2 = "Proyecto1" ascii //weight: 1
        $x_1_3 = "InfectModule" ascii //weight: 1
        $x_1_4 = "Qapkrvkle,DkngQ{qvgoM`hgav" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

