rule Ransom_MSIL_KarmaLock_A_2147718315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KarmaLock.A"
        threat_id = "2147718315"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KarmaLock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"Karma Decryptor\" software" ascii //weight: 1
        $x_1_2 = "karma Ransomware" ascii //weight: 1
        $x_1_3 = "/xUser.php?user=" ascii //weight: 1
        $x_1_4 = "# DECRYPT MY FILES #.html" ascii //weight: 1
        $x_1_5 = {6b 61 72 6d 61 [0-15] 2e 6f 6e 69 6f 6e 2f 78 31 32 33 34}  //weight: 1, accuracy: Low
        $x_1_6 = {26 74 72 79 3d 31 26 73 74 61 74 75 73 3d 30 00}  //weight: 1, accuracy: High
        $x_1_7 = {57 69 6e 64 6f 77 73 54 75 6e 65 55 70 2e 52 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_MSIL_KarmaLock_A_2147718340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/KarmaLock.A!!KarmaLock.gen!A"
        threat_id = "2147718340"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KarmaLock"
        severity = "Critical"
        info = "KarmaLock: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"Karma Decryptor\" software" ascii //weight: 1
        $x_1_2 = "karma Ransomware" ascii //weight: 1
        $x_1_3 = "/xUser.php?user=" ascii //weight: 1
        $x_1_4 = "# DECRYPT MY FILES #.html" ascii //weight: 1
        $x_1_5 = {6b 61 72 6d 61 [0-15] 2e 6f 6e 69 6f 6e 2f 78 31 32 33 34}  //weight: 1, accuracy: Low
        $x_1_6 = {26 74 72 79 3d 31 26 73 74 61 74 75 73 3d 30 00}  //weight: 1, accuracy: High
        $x_1_7 = {57 69 6e 64 6f 77 73 54 75 6e 65 55 70 2e 52 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

