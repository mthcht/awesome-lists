rule TrojanDownloader_Java_Nepift_A_2147659071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Java/Nepift.A"
        threat_id = "2147659071"
        type = "TrojanDownloader"
        platform = "Java: Java binaries (classes)"
        family = "Nepift"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NewApplet.java" ascii //weight: 1
        $x_1_2 = "Wi50eHQgZWNobyB" ascii //weight: 1
        $x_1_3 = "ZnRwLmRyaXZlaHEuY29t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

