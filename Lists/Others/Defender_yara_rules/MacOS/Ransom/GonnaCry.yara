rule Ransom_MacOS_GonnaCry_A_2147957618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/GonnaCry.A"
        threat_id = "2147957618"
        type = "Ransom"
        platform = "MacOS: "
        family = "GonnaCry"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".GNNCRY" ascii //weight: 2
        $x_2_2 = "all your files below have been encrypted, cheers" ascii //weight: 2
        $x_1_3 = "KEY = %s IV = %s PATH = %s" ascii //weight: 1
        $x_1_4 = "your_encrypted_files.txt" ascii //weight: 1
        $x_1_5 = "doc docx xls xls" ascii //weight: 1
        $x_1_6 = "Desktop/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

