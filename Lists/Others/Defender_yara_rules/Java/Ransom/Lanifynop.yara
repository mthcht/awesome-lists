rule Ransom_Java_Lanifynop_A_2147753349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Java/Lanifynop.A!ibt"
        threat_id = "2147753349"
        type = "Ransom"
        platform = "Java: Java binaries (classes)"
        family = "Lanifynop"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_JAVAHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "srw,.pef,.ptx,.r3d,.rw2,.rwl,.raw,.raf,.orf,.nrw,.mrwref,.mef,.erf,.kdc,.dcr,.cr2,.crw,.bay,.sr2,.srf,.arw,.3fr,.dng,.jpe,.jpg" ascii //weight: 1
        $x_1_2 = "Encrypting file: %s%n" ascii //weight: 1
        $x_1_3 = "README_files.txt" ascii //weight: 1
        $x_1_4 = "java/security/SecureRandom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

