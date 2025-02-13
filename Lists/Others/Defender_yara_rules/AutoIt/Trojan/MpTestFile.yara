rule Trojan_AutoIt_MpTestFile_W_2147696987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AutoIt/MpTestFile.W"
        threat_id = "2147696987"
        type = "Trojan"
        platform = "AutoIt: AutoIT scripts"
        family = "MpTestFile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "975f5676-826d-4550-9477-a288cbbbb8b2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

