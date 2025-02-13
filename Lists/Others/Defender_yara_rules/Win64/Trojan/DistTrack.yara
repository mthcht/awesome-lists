rule Trojan_Win64_DistTrack_D_2147731424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/DistTrack.D"
        threat_id = "2147731424"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "DistTrack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ElRawDisk" wide //weight: 1
        $x_1_2 = "#{8A6DB7D2-FECF-41ff-9A92-6EDA696613DE}#" wide //weight: 1
        $x_1_3 = "#{9A6DB7D2-FECF-41ff-9A92-6EDA696613DF}#" wide //weight: 1
        $x_1_4 = "System\\CurrentControlSet\\Control\\NetworkProvider\\Order" wide //weight: 1
        $x_1_5 = "{25EC4453-AB06-4b3f-BCF0-B260A68B64C9}" ascii //weight: 1
        $x_1_6 = "{82B5234F-DF61-4638-95D5-341CAD244D19}" ascii //weight: 1
        $x_1_7 = "NDI4Cg bf039ab1663ed782124ba04d4e457892" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

