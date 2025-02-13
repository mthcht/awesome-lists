rule Ransom_Linux_CerberRansom_A_2147895748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/CerberRansom.A"
        threat_id = "2147895748"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "CerberRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii //weight: 1
        $x_1_2 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

